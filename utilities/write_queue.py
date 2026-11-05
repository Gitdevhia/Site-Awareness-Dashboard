"""
write_queue.py - shared, durable write queue for SAD.

Problem this solves: sad.db lives on a network share, and multiple
gui.py processes plus a multithreaded discovery scan's many worker
threads all want to write to it at once. SQLite's own file locking
over SMB is slow/unreliable for anything beyond "one writer, briefly" -
a long write, or several concurrent short ones, locks everyone else
out of the live file for its whole duration.

Instead of writing to sad.db directly, a write goes through
queue_write() here, which drops a small durable JSON file describing
the intended operation into a shared spool directory next to sad.db.
Actually applying queued items to the live database is try_drain()'s
job - exactly one caller does that at a time (enforced by a simple
claim-a-lock-file protocol), turning "many writers fighting over the
live file" into "many writers appending to a directory (safe, no
coordination needed) + one drainer applying a backlog in small,
fast, individually-committed steps".

Every operation queued here is expected to be idempotent and
resolvable by real-world key (site octet, hostname, device-pair, etc)
- not a raw SQL diff - matching how db.py's upsert-style functions
already work. That's what makes replay order mostly not matter and
makes a half-finished drain (crash mid-loop) safe to just resume
later: nothing here pre-assigns a row id, so there's no possibility
of a primary-key collision the way there would be if two independent
copies of the database were merged back together instead.

There is deliberately no always-on process reading this queue. Every
gui.py instance is a potential drainer: an action queues its own
write and then immediately tries to drain the whole queue itself
(queue_and_apply(), the common case - a single user working alone
sees no lag at all), and gui.py also runs a periodic background drain
on a timer so an idle-but-open GUI keeps the queue moving even when
nobody's actively clicking anything. If literally no GUI is open,
queued items just wait safely on disk until the next one is.
"""
import collections
import json
import os
import sys
import tempfile
import threading
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import db  # noqa: E402


# Guards every read OR write of db.CURRENT_USER / CURRENT_CREDENTIAL_STORE
# from this module. Needed because gui.py's periodic background drain
# briefly impersonates a queued item's original requester (see
# _drain_locked()) on a thread that isn't the main GUI thread. Without
# this lock, a same-process,
# same-moment call to queue_write() on the main thread (e.g. the user
# clicking "Add Site" right as the background timer's drain is
# mid-impersonation) could read CURRENT_USER while it's still swapped
# to someone else's identity, and record the wrong "queued_by" on a
# brand new item. The lock makes "touch CURRENT_USER" fully serialized
# within this process, so that window can't be observed from anywhere
# else in write_queue.py. It does NOT protect code outside this module
# that logs activity directly (Discovery/Command Runner still do,
# until they're migrated onto the queue too) - that's a narrow,
# separately-tracked residual gap, not something this lock claims to
# close.
_user_context_lock = threading.RLock()


QUEUE_DIRNAME = "write_queue"
LOCK_FILENAME = ".drain.lock"
STALE_LOCK_SECONDS = 120  # a lock older than this is assumed abandoned (crashed drainer)


# A small process-local cache of recently-drained outcomes, keyed by
# request_id, populated by EVERY _drain_locked()
# call regardless of who triggered it. queue_and_wait() (below) needs
# this because the thread that queues an item is often not the one
# whose try_drain() call ends up actually applying it - a multithreaded
# discovery scan has many worker threads all calling try_drain() in a
# tight loop, and only one of them wins the lock on any given attempt.
# Without a shared cache, a worker whose own try_drain() call returned
# {} (lock held elsewhere) would have no way to learn the result of an
# item another worker thread just applied on its behalf - and that
# result (e.g. a newly upserted device's row id) is exactly what
# discover_site() needs back synchronously to keep walking correctly.
# Bounded (deque of ids + a matching dict) so a long scan doesn't grow
# this unboundedly - queue_and_wait() always pops its own entry right
# after reading it, so under normal operation this rarely holds more
# than a handful of entries at once; the bound is just a safety net.
_outcome_cache_lock = threading.Lock()
_recent_outcomes = {}
_recent_outcome_order = collections.deque()
_RECENT_OUTCOMES_MAX = 2000


def _remember_outcome(request_id: str, outcome: dict) -> None:
    with _outcome_cache_lock:
        _recent_outcomes[request_id] = outcome
        _recent_outcome_order.append(request_id)
        while len(_recent_outcome_order) > _RECENT_OUTCOMES_MAX:
            oldest = _recent_outcome_order.popleft()
            _recent_outcomes.pop(oldest, None)


def _take_outcome(request_id: str):
    with _outcome_cache_lock:
        return _recent_outcomes.pop(request_id, None)


def _queue_dir(db_path: str = None) -> str:
    db_path = db_path or db.DB_PATH
    base = os.path.dirname(os.path.abspath(db_path))
    path = os.path.join(base, QUEUE_DIRNAME)
    os.makedirs(path, exist_ok=True)
    return path


# Maps a queued action's name to the db.py function that actually
# applies it. Every one of these takes `conn` as its first argument -
# queue_write() callers never pass conn themselves, since which
# connection (and which process) ends up applying a queued item isn't
# decided until drain time, not at queue time.
ACTIONS = {
    "add_site_manual": db.add_site_manual,
    "soft_delete_site": db.soft_delete_site,
    "add_device_manual": db.add_device_manual,
    "soft_delete_device": db.soft_delete_device,
    "set_site_identity": db.set_site_identity,
    "set_device_as_seed": db.set_device_as_seed,
    "set_device_as_arp_seed": db.set_device_as_arp_seed,
    "clear_device_as_arp_seed": db.clear_device_as_arp_seed,
    "set_device_arp_override_ip": db.set_device_arp_override_ip,
    "set_device_marked_stale": db.set_device_marked_stale,
    "merge_devices": db.merge_devices,
    "move_device_to_site": db.move_device_to_site,
    "touch_device_seen": db.touch_device_seen,
    "auto_seed_singleton_sites": db.auto_seed_singleton_sites,

    # Raw discovery-time write functions. Unlike the actions above,
    # none of these call db.log_activity() internally - a multi-site
    # scan can touch thousands of devices/links/ARP entries, and
    # logging every single one would flood the activity log with noise
    # nobody wants to read. The one activity_log entry for an entire
    # scan is written up front by run_for_sites() itself, independently
    # of the queue.
    "upsert_device": db.upsert_device,
    "record_device_ip": db.record_device_ip,
    "upsert_link": db.upsert_link,
    "upsert_client": db.upsert_client,
    "stage_mac_table_raw": db.stage_mac_table_raw,
    "mark_site_run": db.mark_site_run,
    "mark_site_mac_table_run": db.mark_site_mac_table_run,
    "upsert_arp_entry": db.upsert_arp_entry,
    "mark_site_arp_run": db.mark_site_arp_run,
    "get_or_create_unassigned_site": db.get_or_create_unassigned_site,
    "upsert_tunnel_interface": db.upsert_tunnel_interface,
    "mark_site_tunnel_run": db.mark_site_tunnel_run,
    # Not per-site like everything else above - match_tunnels() re-
    # correlates the WHOLE tunnel_interfaces table every time it runs
    # (see its own docstring for why this has to be global rather than
    # scoped to whichever site just finished collecting). Queued the
    # same way as any other write so it's still serialized against
    # every other writer on a network-shared sad.db, just with no
    # site-scoped kwargs to pass.
    "match_tunnels": db.match_tunnels,
    "record_config_snapshot": db.record_config_snapshot,
    "record_config_pull_result": db.record_config_pull_result,
    "import_kg_snapshot": db.import_kg_snapshot,
    "set_kg_site": db.set_kg_site,
    "import_kg_site_map": db.import_kg_site_map,
    "soft_delete_kg_device": db.soft_delete_kg_device,
    "add_manual_kg": db.add_manual_kg,
    "update_manual_kg": db.update_manual_kg,
}


# A "batch" queued item isn't one call into ACTIONS itself - it
# carries a list of ordinary sub-operations (each one an {"action":
# ..., "kwargs": ...} pair naming a real ACTIONS entry), and
# _drain_locked() applies every one of them against a SINGLE
# connection, committing once at the end. That's the point: over a
# network-shared sad.db, each individually-queued write costs its own
# connection-open/commit/close plus its own queue-file create/delete/
# lock-claim round trip, and a site's ARP collection alone can produce
# 1000+ upsert_arp_entry calls - batching related writes together
# turns that into a single round trip. See queue_batch_and_wait()
# below for the caller-facing entry point.
BATCH_ACTION = "batch"


def queue_write(action: str, **kwargs) -> str:
    """Durably queues one operation for later application against the
    live database. Returns the item's request id, so a caller that
    goes on to drain the queue itself (queue_and_apply(), below) can
    recognize its own item's outcome afterward. Does NOT touch the
    live database itself - this only ever writes one small file.
    """
    if action != BATCH_ACTION and action not in ACTIONS:
        raise ValueError(f"Unknown write-queue action: {action!r}")
    request_id = uuid.uuid4().hex
    with _user_context_lock:
        queued_by = getattr(db, "CURRENT_USER", None)
        queued_credential_store = getattr(db, "CURRENT_CREDENTIAL_STORE", None)
    record = {
        "id": request_id,
        "action": action,
        "kwargs": kwargs,
        "queued_at": time.time(),
        "queued_by": queued_by,
        "queued_credential_store": queued_credential_store,
    }
    qdir = _queue_dir()
    # Filename is prefixed with a sortable timestamp so a directory
    # listing comes back in roughly enqueue order - not a hard
    # guarantee under clock skew across machines, but good enough
    # given every queued operation is independently idempotent and
    # doesn't depend on exact ordering to reach the right end state.
    filename = f"{time.time():020.6f}_{request_id}.json"
    final_path = os.path.join(qdir, filename)
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_", dir=qdir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(record, f)
        os.replace(tmp_path, final_path)  # atomic rename within the same directory
    except BaseException:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise
    return request_id


def _claim_drain_lock(qdir: str) -> bool:
    """Atomically claims the shared drain lock via exclusive file
    creation (O_CREAT | O_EXCL - fails if the file already exists,
    which is what makes this safe with no other coordination). If the
    existing lock looks stale (older than STALE_LOCK_SECONDS), assumes
    its owner crashed mid-drain and steals it - there's no watchdog
    process to notice a stuck lock otherwise, and with no always-on
    drainer, a permanently wedged lock would mean nothing ever gets
    applied again until someone manually intervenes.
    """
    lock_path = os.path.join(qdir, LOCK_FILENAME)
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, str(time.time()).encode("utf-8"))
        os.close(fd)
        return True
    except FileExistsError:
        try:
            age = time.time() - os.path.getmtime(lock_path)
        except OSError:
            return False  # lock vanished mid-check - treat as "someone else has it", the safe default
        if age > STALE_LOCK_SECONDS:
            try:
                os.remove(lock_path)
            except OSError:
                return False  # someone else already cleaned it up / re-claimed it first
            return _claim_drain_lock(qdir)
        return False


def _release_drain_lock(qdir: str) -> None:
    try:
        os.remove(os.path.join(qdir, LOCK_FILENAME))
    except OSError:
        pass


def try_drain(db_path: str = None) -> dict:
    """Attempts to claim the drain lock and, if successful, applies
    every item currently in the spool directory to the live database,
    oldest first. Returns {request_id: {"ok": bool, "result": ...,
    "error": ...}} for every item actually processed this call -
    empty if the lock couldn't be claimed (someone else is already
    draining right now) or if the queue was empty.

    Safe to call from anywhere, anytime, as often as you like -
    callers never need to know or care whether they personally end up
    being the drainer this time; if not, this just returns having
    done nothing.
    """
    qdir = _queue_dir(db_path)
    if not _claim_drain_lock(qdir):
        return {}
    try:
        return _drain_locked(qdir, db_path)
    finally:
        _release_drain_lock(qdir)


def _drain_locked(qdir: str, db_path: str = None) -> dict:
    outcomes = {}
    conn_path = db_path or db.DB_PATH
    items = sorted(
        f for f in os.listdir(qdir)
        if f.endswith(".json") and not f.startswith(".tmp_")
    )
    for filename in items:
        full_path = os.path.join(qdir, filename)
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                record = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            # Can't even parse it - leave it in place rather than
            # silently discarding someone's intended change because it
            # happened to be unreadable this one time (shouldn't
            # normally happen given the atomic write, but this is the
            # one place in the whole pipeline where losing an item
            # would be silent and permanent, so it errs toward leaving
            # evidence behind instead).
            print(f"Warning: could not read queued write {filename}: {e}")
            continue

        action = record.get("action")
        request_id = record.get("id", filename)
        is_batch = action == BATCH_ACTION
        func = None if is_batch else ACTIONS.get(action)
        if not is_batch and func is None:
            outcomes[request_id] = {"ok": False, "result": None, "error": f"unknown action {action!r}"}
            _remember_outcome(request_id, outcomes[request_id])
            print(f"Warning: skipping queued write with unknown action {action!r} ({filename})")
            continue

        # Whoever actually ends up draining this item may not be who
        # queued it (that's the whole point of the queue) - but the
        # activity log needs to credit the ORIGINAL requester, not
        # whichever process happened to be the one applying it. Every
        # db.py write function logs using the module-level
        # db.CURRENT_USER/CURRENT_CREDENTIAL_STORE globals, so those
        # are temporarily impersonated for the duration of this one
        # item's application, then restored - even on failure - so a
        # drain never permanently changes whose name this process's
        # OWN actions get logged under afterward. Held under
        # _user_context_lock so nothing else in this process (like a
        # foreground click queuing a brand new item) can observe the
        # globals mid-impersonation - see the lock's own docstring.
        with _user_context_lock:
            prior_user = db.CURRENT_USER
            prior_store = db.CURRENT_CREDENTIAL_STORE
            db.CURRENT_USER = record.get("queued_by") or prior_user
            db.CURRENT_CREDENTIAL_STORE = record.get("queued_credential_store") or prior_store
            try:
                try:
                    if is_batch:
                        # All sub-ops share ONE connection and commit
                        # together (db.get_conn() only calls
                        # conn.commit() if the with-block exits
                        # cleanly) - if any sub-op raises, nothing in
                        # this batch is persisted, matching the
                        # all-or-nothing semantics of "one step" for a
                        # whole site-phase. A malformed sub-op action
                        # name fails the same way, before touching the
                        # database.
                        ops = record.get("kwargs", {}).get("ops", [])
                        sub_results = []
                        with db.get_conn(conn_path) as conn:
                            for op in ops:
                                op_action = op.get("action")
                                op_func = ACTIONS.get(op_action)
                                if op_func is None:
                                    raise ValueError(f"unknown action {op_action!r} inside batch")
                                sub_results.append(op_func(conn, **op.get("kwargs", {})))
                        result = sub_results
                    else:
                        with db.get_conn(conn_path) as conn:
                            result = func(conn, **record.get("kwargs", {}))
                    outcomes[request_id] = {"ok": True, "result": result, "error": None}
                    _remember_outcome(request_id, outcomes[request_id])
                except Exception as e:
                    # One bad item shouldn't wedge the whole queue
                    # behind it - record the failure, leave its file
                    # in place for later retry/inspection, and keep
                    # draining the rest.
                    outcomes[request_id] = {"ok": False, "result": None, "error": str(e)}
                    _remember_outcome(request_id, outcomes[request_id])
                    print(f"Warning: queued write {filename} ({action}) failed: {e}")
                    continue
            finally:
                # Restore this process's own identity regardless of
                # what happened above - impersonating the original
                # requester must never leak past the one item it was
                # for.
                db.CURRENT_USER = prior_user
                db.CURRENT_CREDENTIAL_STORE = prior_store

        try:
            os.remove(full_path)
        except OSError:
            pass

    return outcomes


def queue_and_apply(action: str, **kwargs):
    """Convenience for the common, uncontended case: queue the write,
    then immediately try to drain the whole spool (not just this call's
    own item - draining is all-or-nothing per attempt, so this also
    helps clear out anything left behind by someone else).

    Returns (applied, result):
      - applied=True  - this call's own item was actually applied, by
        this process, just now. `result` is whatever the underlying
        db.py function returned - callers use this for the normal,
        immediate feedback (a revival notice, an impact count, etc.),
        exactly as if the queue didn't exist.
      - applied=False - the item is durably queued but wasn't applied
        yet, because someone else is mid-drain right now. It WILL be
        applied soon (by this GUI's own periodic drain timer if
        nothing else gets to it first) - just not in time for this
        call to report the outcome. `result` is None in this case;
        callers should show a lightweight "queued" notice instead of
        a definite result.

    Raises whatever the underlying db.py function raised, if this call
    was the one that applied the item and it failed - same as calling
    the db.py function directly would have, so existing try/except
    error-dialog handling in callers doesn't need to change.
    """
    request_id = queue_write(action, **kwargs)
    outcomes = try_drain()
    outcome = outcomes.get(request_id)
    if outcome is None:
        return False, None
    if not outcome["ok"]:
        raise RuntimeError(outcome["error"])
    return True, outcome["result"]


def queue_and_wait(action: str, timeout: float = 30.0, poll_interval: float = 0.1, **kwargs):
    """Queues a write and blocks the calling thread until it has
    definitely been applied, returning the underlying db.py function's
    result directly (e.g. a newly upserted device's row id) - unlike
    queue_and_apply(), which gives up after one drain attempt and
    reports "queued, not yet applied" for the caller to handle async.

    This is what multithreaded discovery needs instead:
    discover_site()'s CDP walk is a sequential BFS that has to know a
    neighbor's real device_id before it can write the link to it, so a
    "maybe applied, maybe not yet" result isn't usable there the way it
    is for a GUI button click. Safe to call from many worker threads at
    once - every call keeps retrying try_drain() itself (so a busy
    queue still gets drained by whichever thread happens to grab the
    lock) and reads the outcome back from the process-local cache
    populated by ANY thread's successful drain, not just its own.

    Raises RuntimeError if the write itself failed once applied (same
    as queue_and_apply()), or TimeoutError if it's still not applied
    after `timeout` seconds - which the caller should treat as a real
    failure (something's very wrong - a wedged stale lock that keeps
    getting re-claimed by something that never finishes, for example),
    not silently ignore.
    """
    qdir = _queue_dir()
    request_id = queue_write(action, **kwargs)
    deadline = time.time() + timeout
    requeued = False

    while True:
        try_drain()
        outcome = _take_outcome(request_id)
        if outcome is not None:
            if not outcome["ok"]:
                raise RuntimeError(outcome["error"])
            return outcome["result"]

        if time.time() >= deadline:
            # Still not resolved. Distinguish "just slow" (its file is
            # still sitting in the spool - normal under heavy
            # contention, nothing to do but keep waiting) from "its
            # file is gone but we never saw an outcome" (some other
            # process's drain applied it and exited before we ever
            # checked the cache - only possible across separate
            # processes, since the cache is shared within this one).
            # Every action registered for queue_and_wait() is a pure,
            # idempotent upsert keyed by real-world identity, so in the
            # second case it's always safe to simply queue the exact
            # same write again and wait for THAT one definitively -
            # worst case it's a harmless no-op re-application of data
            # already there. Only attempted once, to avoid ever looping
            # forever against something more fundamentally stuck.
            still_pending = any(
                fn.endswith(f"_{request_id}.json")
                for fn in os.listdir(qdir)
                if fn.endswith(".json") and not fn.startswith(".tmp_")
            )
            if still_pending:
                raise TimeoutError(
                    f"queue_and_wait: {action!r} (request {request_id}) was still queued, "
                    f"unapplied, after {timeout:.0f}s - the write queue may be stuck."
                )
            if requeued:
                raise TimeoutError(
                    f"queue_and_wait: {action!r} (request {request_id}) vanished from the queue "
                    f"without a recorded outcome, twice in a row - giving up."
                )
            request_id = queue_write(action, **kwargs)
            requeued = True
            deadline = time.time() + timeout
            continue

        time.sleep(poll_interval)


def queue_batch_and_wait(ops: list, timeout: float = 30.0, poll_interval: float = 0.1) -> list:
    """Batched sibling of queue_and_wait(): queues a whole list of
    sub-operations as ONE spool item and blocks until the whole batch
    has been applied as a single connection/commit, returning the list
    of each sub-op's own result in the same order `ops` was given.

    `ops` is a list of {"action": <ACTIONS name>, "kwargs": {...}}
    dicts - each one exactly what you'd otherwise pass to
    queue_and_wait() individually. Use this instead of calling
    queue_and_wait() once per sub-op whenever a whole set of writes
    naturally belongs to one step (a site's full ARP pull, a full MAC
    correlation pass, or - for CDP - one neighbor's device/IP/link
    writes) and doesn't need any other write to be visible in between.

    Raises ValueError up front (before queuing anything) if any op
    names an unknown action, so a typo fails fast instead of silently
    losing part of a batch at drain time. Raises RuntimeError if the
    batch was applied but failed (same meaning as queue_and_wait():
    the whole batch failed together and nothing in it was committed),
    or TimeoutError under the same conditions queue_and_wait() would.
    """
    for op in ops:
        op_action = op.get("action") if isinstance(op, dict) else None
        if op_action not in ACTIONS:
            raise ValueError(f"Unknown write-queue action inside batch: {op_action!r}")
    return queue_and_wait(BATCH_ACTION, timeout=timeout, poll_interval=poll_interval, ops=ops)