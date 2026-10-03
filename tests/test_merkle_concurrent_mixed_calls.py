"""Concurrent regression tests for the shared state of ``MerkleSigner``.

These tests interleave the five state-touching primitives — ``sign``,
``sign_batch``, ``sign_selected``, ``advance_to`` and ``checkpoint`` (plus
the locked ``next_index`` / ``remaining`` reads) — on one signer from many
threads. They do not assume which thread wins a race. Instead every call is
recorded with its start/end timestamps, its return value and any exception,
and the whole record is checked against the *existence* of a legal serial
order:

* the order must respect the real-time happens-before edge (a call that
  finished before another started is ordered first);
* successful single signs consume exactly the current leaf, batches consume
  a run of consecutive leaves, explicit selections advance to just past
  their last leaf (every skipped leaf is voided forever), and
  ``advance_to`` jumps forward or stays put;
* every returned signature verifies against its own message under
  :func:`merkle_verify` and no leaf index is ever returned twice;
* a snapshot may only show a complete state immediately before or after a
  call it overlaps — never a half-consumed batch or selection;
* every snapshot round-trips through ``from_checkpoint`` with the same
  public key, ``next_index`` and ``remaining`` as the state it captured, and
  an isolated restored signer spends exactly the saved next leaf;
* the final signer state equals the state after that same serial order —
  distinct signature indices alone are not accepted as success.

The losing-call side of the same races is covered too: capacity-valid
batches larger than the remaining capacity and post-exhaustion single signs
or legal non-empty selections raise :class:`KeyExhaustedError`; selections
behind the current index and backwards jumps raise ``ValueError`` while
leaves remain; a structurally valid batch with an illegal message raises
``TypeError`` and consumes nothing. Empty batches stay successful even when
exhausted (returning the empty tuple), and equal-target jumps return the
same index twice.

Only a public, deterministic seed-built signer (``from_seed``) is used, so
the runs are fully reproducible.
"""

from __future__ import annotations

import hashlib
import threading
import time
import unittest
from dataclasses import dataclass
from itertools import count
from typing import Any, Callable

from pqattest import (
    KeyExhaustedError,
    MerkleSigner,
    merkle_verify,
)

# Small trees as required by the regression: 16 leaves for w=4 and w=8.
_HEIGHT = 4
_LEAF_COUNT = 1 << _HEIGHT
# Fixed public test input: no randomness is drawn anywhere in this module.
_SEED = hashlib.sha256(b"pqattest/test/merkle-concurrent-mixed-calls/v1").digest()


def _build_signer(w: int) -> MerkleSigner:
    return MerkleSigner.from_seed(_SEED, w=w, height=_HEIGHT)


@dataclass
class Record:
    """One observed call: identity, span, outcome and leaf bookkeeping.

    Successful calls carry the exact ``(message, signature)`` pairs they
    returned; failed calls additionally carry the attempted selection
    indices / batch size so the serial-order search can decide at which
    states the documented exception is legal.
    """

    seq: int
    kind: str
    start: int
    end: int
    success: bool
    error: BaseException | None = None
    pairs: tuple[tuple[Any, Any], ...] = ()
    indices: tuple[int, ...] = ()
    attempted_indices: tuple[int, ...] = ()
    attempted_size: int = 0
    before: int | None = None
    after: int | None = None
    target: int | None = None
    snapshot: int | None = None
    blob: bytes | None = None
    observed: int | None = None


class History:
    """Thread-safe append log of :class:`Record` values."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seq = count()
        self.records: list[Record] = []

    def append(self, record: Record) -> None:
        with self._lock:
            self.records.append(record)

    def execute(
        self,
        kind: str,
        fn: Callable[[], Any],
        *,
        messages: tuple[Any, ...] = (),
        indices: tuple[int, ...] = (),
        target: int | None = None,
    ) -> None:
        """Run one call and record its span, outcome and returned payload."""
        seq = next(self._seq)
        start = time.perf_counter_ns()
        try:
            result = fn()
        except BaseException as exc:
            self.append(
                Record(
                    seq=seq,
                    kind=kind,
                    start=start,
                    end=time.perf_counter_ns(),
                    success=False,
                    error=exc,
                    attempted_indices=indices,
                    attempted_size=len(messages),
                    target=target,
                )
            )
            return

        end = time.perf_counter_ns()
        if kind == "sign":
            signature = result
            self.append(
                Record(
                    seq=seq, kind=kind, start=start, end=end, success=True,
                    pairs=((messages[0], signature),),
                    indices=(signature.index,),
                )
            )
        elif kind in {"batch", "selected"}:
            signatures = tuple(result)
            self.append(
                Record(
                    seq=seq, kind=kind, start=start, end=end, success=True,
                    pairs=tuple(zip(messages, signatures)),
                    indices=tuple(signature.index for signature in signatures),
                )
            )
        elif kind == "advance":
            before, after = result
            self.append(
                Record(
                    seq=seq, kind=kind, start=start, end=end, success=True,
                    before=before, after=after,
                )
            )
        elif kind == "checkpoint":
            blob = result
            snapshot = MerkleSigner.from_checkpoint(blob).next_index
            self.append(
                Record(
                    seq=seq, kind=kind, start=start, end=end, success=True,
                    snapshot=snapshot, blob=blob,
                )
            )
        elif kind in {"next_index", "remaining"}:
            self.append(
                Record(
                    seq=seq, kind=kind, start=start, end=end, success=True,
                    observed=result,
                )
            )
        else:  # pragma: no cover - defensive
            raise AssertionError(f"unknown record kind: {kind}")


def _applies(record: Record, state: int, leaf_count: int) -> bool:
    """Whether ``record`` is legal when the signer is at ``state``.

    Every successful mutator pins the state it ran at through its return
    value; the only records legal at more than one state are failed calls,
    empty batches and (for selections) the entry state before the gap.
    """
    if record.success:
        kind = record.kind
        if kind == "sign":
            return state < leaf_count and record.indices == (state,)
        if kind == "batch":
            if not record.indices:
                return True  # empty batch succeeds at any state
            return record.indices == tuple(
                range(state, state + len(record.indices))
            )
        if kind == "selected":
            return (
                state <= record.indices[0]
                and record.indices[-1] < leaf_count
            )
        if kind == "advance":
            return record.before == state and record.after >= state
        if kind == "checkpoint":
            return record.snapshot == state
        if kind == "next_index":
            return record.observed == state
        if kind == "remaining":
            return record.observed == leaf_count - state
        return False

    # Failure legality follows the implementation's fixed error order.
    kind = record.kind
    if kind == "sign":
        return isinstance(record.error, KeyExhaustedError) and state == leaf_count
    if kind == "batch":
        if isinstance(record.error, KeyExhaustedError):
            # The tuple was structurally valid but did not fit any more.
            return state + record.attempted_size > leaf_count
        return isinstance(record.error, TypeError)
    if kind == "selected":
        if isinstance(record.error, KeyExhaustedError):
            return state == leaf_count
        if isinstance(record.error, ValueError):
            return (
                state < leaf_count and record.attempted_indices[0] < state
            )
        return False
    if kind == "advance":
        return isinstance(record.error, ValueError) and record.target < state
    return False


def _next_state(record: Record, state: int) -> int:
    if not record.success:
        return state
    if record.kind == "sign":
        return state + 1
    if record.kind == "batch":
        return state + len(record.indices)
    if record.kind == "selected":
        return record.indices[-1] + 1
    if record.kind == "advance":
        return record.after
    return state


def _candidate_state_count(record: Record, leaf_count: int) -> int:
    """Number of states at which ``record`` can apply (search heuristic)."""
    if record.success:
        if record.kind == "selected":
            return record.indices[0] + 1
        if record.kind == "batch" and not record.indices:
            return leaf_count + 1
        return 1
    if record.kind == "sign":
        return 1
    if record.kind == "batch":
        if isinstance(record.error, KeyExhaustedError):
            return record.attempted_size
        return leaf_count + 1  # TypeError can occur at any state
    if record.kind == "selected":
        if isinstance(record.error, KeyExhaustedError):
            return 1
        return leaf_count  # ValueError once the front moved past index 0
    if record.kind == "advance":
        return leaf_count - record.target
    return leaf_count + 1


def find_serial_order(
    records: list[Record], leaf_count: int
) -> list[Record] | None:
    """Return a legal serial order of ``records`` or ``None`` if none exists.

    The search is a depth-first scan over orders restricted by the real-time
    happens-before edge: a record is eligible only after every record whose
    end is no later than its start has already been placed.
    """
    size = len(records)
    full = (1 << size) - 1
    predecessors = [0] * size
    for i in range(size):
        for j in range(size):
            if i != j and records[j].end <= records[i].start:
                predecessors[i] |= 1 << j

    order: list[int] = []
    dead: set[tuple[int, int]] = set()

    def search(placed: int, state: int) -> bool:
        if placed == full:
            return True
        key = (placed, state)
        if key in dead:
            return False
        ready = []
        for i in range(size):
            if ((placed >> i) & 1) or (predecessors[i] & ~placed):
                continue
            if _applies(records[i], state, leaf_count):
                ready.append(i)
        # Place the most constrained records first so the search collapses to
        # the forced spine and only branches on flexible failures.
        ready.sort(
            key=lambda i: (
                _candidate_state_count(records[i], leaf_count),
                records[i].seq,
            )
        )
        for i in ready:
            order.append(i)
            if search(placed | (1 << i), _next_state(records[i], state)):
                return True
            order.pop()
        dead.add(key)
        return False

    return [records[i] for i in order] if search(0, 0) else None


def _describe(records: list[Record]) -> str:
    lines = []
    for record in records:
        if record.success:
            if record.kind in {"sign", "batch", "selected"}:
                payload = f"indices={record.indices}"
            elif record.kind == "advance":
                payload = f"{record.before}->{record.after}"
            elif record.kind == "checkpoint":
                payload = f"snapshot={record.snapshot}"
            else:
                payload = f"observed={record.observed}"
            status = "ok "
        else:
            payload = (
                f"attempt={record.attempted_indices or record.attempted_size} "
                f"err={type(record.error).__name__}: {record.error}"
            )
            status = "ERR"
        lines.append(
            f"  #{record.seq:<3} {status} {record.kind:<11} {payload}"
        )
    return "\n".join(lines)


class _ThreadGroup:
    """Start/join workers and fail the test on escape or hang.

    Every worker waits on the same barrier and, when ``yield_turn`` is set,
    hands the scheduler one turn before invoking its call. The plain GIL
    otherwise lets the first released thread run straight into the signing
    lock and win almost every race; ``sleep(0)`` makes the lock hand-off
    genuinely contended so distinct serial orders are exercised across
    runs. Waiting for (and possibly failing to acquire) the lock is part of
    the recorded call, so loser spans really do overlap winner spans.
    """

    def __init__(
        self, testcase: unittest.TestCase, size: int, *, yield_turn: bool = True
    ) -> None:
        self._testcase = testcase
        self._barrier = threading.Barrier(size, timeout=30)
        self._yield_turn = yield_turn
        self._failures: list[tuple[str, BaseException]] = []
        self._failures_lock = threading.Lock()
        self._threads: list[threading.Thread] = []

    def add(self, name: str, target: Callable[[], None]) -> None:
        def worker() -> None:
            self._barrier.wait()
            if self._yield_turn:
                time.sleep(0)
            try:
                target()
            except BaseException as exc:  # anything escaping is a test failure
                with self._failures_lock:
                    self._failures.append((name, exc))

        self._threads.append(threading.Thread(target=worker, name=name))

    def run(self) -> None:
        for thread in self._threads:
            thread.start()
        for thread in self._threads:
            thread.join(timeout=30)
            self._testcase.assertFalse(
                thread.is_alive(), f"worker {thread.name} did not finish"
            )
        if self._failures:
            name, exc = self._failures[0]
            self._testcase.fail(
                f"worker {name} raised {type(exc).__name__}: {exc}"
            )

    @property
    def barrier(self) -> threading.Barrier:
        return self._barrier


class ConcurrentMixedCallsTest(unittest.TestCase):
    """The mixed-call workload, validated as one explainable history."""

    def _assert_history_explained(
        self, signer: MerkleSigner, history: History
    ) -> list[Record]:
        records = history.records
        self.assertTrue(records, "the concurrent run produced no records")
        for record in records:
            self.assertLessEqual(
                record.start,
                record.end,
                f"record #{record.seq} has an invalid time span",
            )
            if not record.success:
                self.assertIsInstance(
                    record.error,
                    (KeyExhaustedError, ValueError, TypeError),
                    f"record #{record.seq} raised {record.error!r}",
                )

        order = find_serial_order(records, _LEAF_COUNT)
        self.assertIsNotNone(
            order,
            "concurrent history matches no legal serial order:\n"
            + _describe(records),
        )
        assert order is not None  # for type checkers

        # Recompute the state along the found order; every prefix state is a
        # complete state a checkpoint may legitimately reflect.
        prefix_states = {0}
        cursor = 0
        for record in order:
            cursor = _next_state(record, cursor)
            prefix_states.add(cursor)

        # Final state must follow from that same order — distinct signature
        # indices alone are not sufficient.
        self.assertEqual(
            signer.next_index,
            cursor,
            "final next_index disagrees with the legal serial order",
        )
        self.assertEqual(signer.remaining, _LEAF_COUNT - cursor)

        # One-time leaf rule: every signature verifies for its own message
        # and no leaf index is returned twice.
        signed: dict[int, int] = {}
        for record in records:
            if not record.success or record.kind not in {
                "sign",
                "batch",
                "selected",
            }:
                continue
            for message, signature in record.pairs:
                index = signature.index
                self.assertTrue(
                    merkle_verify(message, signature, signer.public_key),
                    f"signature at leaf {index} fails for its message",
                )
                previous = signed.get(index)
                self.assertIsNone(
                    previous,
                    f"leaf {index} signed twice (records #{previous} and "
                    f"#{record.seq})",
                )
                signed[index] = record.seq

        # Failed calls returned no partial signatures.
        for record in records:
            if not record.success:
                self.assertEqual(
                    record.pairs,
                    (),
                    f"failed record #{record.seq} returned partial signatures",
                )

        # Snapshots reflect complete states of the order, restore with the
        # same public key / next_index / remaining, and an isolated restored
        # copy continues at exactly the saved next leaf.
        for record in records:
            if record.kind != "checkpoint":
                continue
            self.assertIn(
                record.snapshot,
                prefix_states,
                f"snapshot #{record.seq} at state {record.snapshot} is not a "
                "complete prefix state (would expose a half-finished call)",
            )
            restored = MerkleSigner.from_checkpoint(record.blob)
            self.assertEqual(restored.public_key, signer.public_key)
            self.assertEqual(restored.next_index, record.snapshot)
            self.assertEqual(
                restored.remaining, _LEAF_COUNT - record.snapshot
            )
            if record.snapshot < _LEAF_COUNT:
                resumed = restored.sign(f"resume-after-{record.seq}")
                self.assertEqual(
                    resumed.index,
                    record.snapshot,
                    "restored signer must continue at the saved next leaf",
                )
                self.assertTrue(
                    merkle_verify(
                        f"resume-after-{record.seq}",
                        resumed,
                        restored.public_key,
                    )
                )
        # Isolated restores never touched the shared signer.
        self.assertEqual(signer.next_index, cursor)

        return order

    def _run_workload(self, w: int) -> tuple[MerkleSigner, History]:
        signer = _build_signer(w)
        history = History()

        def message(label: str, index: int) -> str:
            return f"w{w}:{label}:{index}"

        # -- Phase A: two consecutive multi-leaf batches compete, with ------
        # -- checkpoints and a read racing them (no half batch visible). ----
        phase_a = _ThreadGroup(self, 3)

        def batch_a(label: str) -> None:
            messages = tuple(message(label, i) for i in range(6))
            history.execute("batch", lambda: signer.sign_batch(messages),
                            messages=messages)

        def snapshots_a() -> None:
            history.execute("checkpoint", signer.checkpoint)
            history.execute("next_index", lambda: signer.next_index)
            history.execute("checkpoint", signer.checkpoint)

        phase_a.add("A-batch-0", lambda: batch_a("A0"))
        phase_a.add("A-batch-1", lambda: batch_a("A1"))
        phase_a.add("A-snapshots", snapshots_a)
        phase_a.run()

        # -- Phase B: the last four leaves are contested in a single nine- -----
        # -- thread race: a gapped explicit selection (13, 15), two single ---
        # -- signs, a skip to 14, four parameter-valid 3-leaf batches that ----
        # -- only fit at state 12, and a snapshot/remaining reader. Every -----
        # -- winner pattern is legal and the history must explain whichever ---
        # -- actually happens. ------------------------------------------------
        phase_b = _ThreadGroup(self, 9)

        def selected_b() -> None:
            indices = (13, 15)
            messages = (message("B-sel-13", 13), message("B-sel-15", 15))
            history.execute(
                "selected",
                lambda: signer.sign_selected(indices, messages),
                messages=messages,
                indices=indices,
            )

        def sign_b(label: str) -> None:
            msg = message(label, 0)
            history.execute("sign", lambda: signer.sign(msg), messages=(msg,))

        def advance_b() -> None:
            history.execute(
                "advance", lambda: signer.advance_to(14), target=14
            )

        def batch_b(worker: int) -> None:
            messages = tuple(message(f"B{worker}", i) for i in range(3))
            history.execute(
                "batch", lambda: signer.sign_batch(messages), messages=messages
            )

        def snapshots_b() -> None:
            history.execute("checkpoint", signer.checkpoint)
            history.execute("remaining", lambda: signer.remaining)
            history.execute("checkpoint", signer.checkpoint)

        phase_b.add("B-selected", selected_b)
        phase_b.add("B-sign-1", lambda: sign_b("B-sign-1"))
        phase_b.add("B-sign-2", lambda: sign_b("B-sign-2"))
        phase_b.add("B-advance", advance_b)
        for worker in range(4):
            phase_b.add(
                f"B-batch-{worker}", lambda worker=worker: batch_b(worker)
            )
        phase_b.add("B-snapshots", snapshots_b)
        phase_b.run()

        # -- Phase C: a single sign, a legal non-empty selection of the last --
        # -- leaf and a one-leaf batch compete for whatever remains; an empty -
        # -- batch succeeds regardless of exhaustion. -------------------------
        phase_c = _ThreadGroup(self, 4)

        def sign_c() -> None:
            msg = message("C-sign", 0)
            history.execute("sign", lambda: signer.sign(msg), messages=(msg,))

        def selected_c() -> None:
            indices = (_LEAF_COUNT - 1,)
            messages = (message("C-sel-last", _LEAF_COUNT - 1),)
            history.execute(
                "selected",
                lambda: signer.sign_selected(indices, messages),
                messages=messages,
                indices=indices,
            )

        def batch_c() -> None:
            messages = (message("C-batch", 0),)
            history.execute("batch", lambda: signer.sign_batch(messages),
                            messages=messages)

        def empty_batch_c() -> None:
            history.execute(
                "batch", lambda: signer.sign_batch(()), messages=()
            )

        phase_c.add("C-sign", sign_c)
        phase_c.add("C-selected", selected_c)
        phase_c.add("C-batch", batch_c)
        phase_c.add("C-empty", empty_batch_c)
        phase_c.run()

        # -- Phase D: an equal jump on the exhausted tail and a final read. --
        history.execute(
            "advance", lambda: signer.advance_to(_LEAF_COUNT),
            target=_LEAF_COUNT,
        )
        history.execute("remaining", lambda: signer.remaining)

        return signer, history

    def test_mixed_calls_w4(self) -> None:
        signer, history = self._run_workload(w=4)
        self._assert_history_explained(signer, history)

    def test_mixed_calls_w8(self) -> None:
        signer, history = self._run_workload(w=8)
        self._assert_history_explained(signer, history)


class GappedSelectionConcurrencyTest(unittest.TestCase):
    """The gap selection voids skipped leaves while snapshots race it."""

    def test_gapped_selection_voids_skips_and_resumes_after_last_pick(self) -> None:
        for w in (4, 8):
            with self.subTest(w=w):
                signer = _build_signer(w)
                history = History()
                group = _ThreadGroup(self, 3)

                def selection() -> None:
                    indices = (2, 4)
                    messages = (f"w{w}:gap-2", f"w{w}:gap-4")
                    history.execute(
                        "selected",
                        lambda: signer.sign_selected(indices, messages),
                        messages=messages,
                        indices=indices,
                    )

                def snapshots(worker: int) -> None:
                    history.execute(
                        "checkpoint",
                        signer.checkpoint,
                    )
                    history.execute(
                        "next_index", lambda: signer.next_index
                    )

                group.add("selection", selection)
                group.add("snapshot-0", lambda: snapshots(0))
                group.add("snapshot-1", lambda: snapshots(1))
                group.run()

                order = find_serial_order(history.records, _LEAF_COUNT)
                self.assertIsNotNone(
                    order,
                    "gapped-selection history matches no legal serial order:\n"
                    + _describe(history.records),
                )
                assert order is not None

                self.assertEqual(signer.next_index, 5)
                self.assertEqual(signer.remaining, _LEAF_COUNT - 5)
                signed = {
                    signature.index
                    for record in history.records
                    if record.success
                    and record.kind in {"sign", "batch", "selected"}
                    for _, signature in record.pairs
                }
                self.assertEqual(signed, {2, 4})
                # The skipped leaves are permanently voided while leaves
                # remain: the failure class is ValueError, not exhaustion.
                for skipped in (0, 1, 3):
                    with self.subTest(w=w, skipped=skipped):
                        with self.assertRaises(ValueError):
                            signer.sign_selected(
                                (skipped,), (f"w{w}:too-late-{skipped}",)
                            )
                with self.assertRaises(ValueError):
                    signer.advance_to(3)
                # Signing resumes right after the last chosen leaf.
                next_signature = signer.sign(f"w{w}:after-gap")
                self.assertEqual(next_signature.index, 5)

                for record in history.records:
                    if record.kind != "checkpoint":
                        continue
                    self.assertIn(record.snapshot, {0, 5})
                    restored = MerkleSigner.from_checkpoint(record.blob)
                    self.assertEqual(restored.public_key, signer.public_key)
                    self.assertEqual(
                        restored.remaining, _LEAF_COUNT - record.snapshot
                    )
                    resumed = restored.sign(f"w{w}:resume-{record.snapshot}")
                    self.assertEqual(resumed.index, record.snapshot)


class ConcurrentFailureContentionTest(unittest.TestCase):
    """Each documented failure class, provoked under real contention."""

    def test_capacity_valid_batches_that_no_longer_fit_raise_exhausted(self) -> None:
        for w in (4, 8):
            with self.subTest(w=w):
                signer = _build_signer(w)
                history = History()
                group = _ThreadGroup(self, 4)

                def batch(worker: int) -> None:
                    # Every batch is parameter-legal at the start (12 <= 16);
                    # only one can still fit once a winner commits.
                    messages = tuple(f"w{w}:fit-{worker}-{i}" for i in range(12))
                    history.execute(
                        "batch",
                        lambda: signer.sign_batch(messages),
                        messages=messages,
                    )

                for worker in range(4):
                    group.add(f"batch-{worker}", lambda worker=worker: batch(worker))
                group.run()

                successes = [
                    record
                    for record in history.records
                    if record.success
                ]
                failures = [
                    record
                    for record in history.records
                    if not record.success
                ]
                self.assertEqual(len(successes), 1)
                self.assertEqual(
                    [signature.index for _, signature in successes[0].pairs],
                    list(range(12)),
                )
                self.assertEqual(len(failures), 3)
                for record in failures:
                    self.assertIsInstance(record.error, KeyExhaustedError)
                    self.assertEqual(record.attempted_size, 12)
                    self.assertEqual(record.pairs, ())
                self.assertEqual(signer.next_index, 12)
                self.assertEqual(signer.remaining, 4)

    def test_exhausted_single_and_selection_raise_exhausted_empty_batch_ok(self) -> None:
        for w in (4, 8):
            with self.subTest(w=w):
                signer = _build_signer(w)
                signer.advance_to(_LEAF_COUNT)
                history = History()
                group = _ThreadGroup(self, 3)

                def single() -> None:
                    msg = f"w{w}:late-single"
                    history.execute(
                        "sign", lambda: signer.sign(msg), messages=(msg,)
                    )

                def selected() -> None:
                    indices = (_LEAF_COUNT - 1,)
                    messages = (f"w{w}:late-selected",)
                    history.execute(
                        "selected",
                        lambda: signer.sign_selected(indices, messages),
                        messages=messages,
                        indices=indices,
                    )

                def empty_batch() -> None:
                    history.execute(
                        "batch", lambda: signer.sign_batch(()), messages=()
                    )

                group.add("single", single)
                group.add("selected", selected)
                group.add("empty-batch", empty_batch)
                group.run()

                by_kind = {record.kind: record for record in history.records}
                self.assertIsInstance(by_kind["sign"].error, KeyExhaustedError)
                self.assertIsInstance(
                    by_kind["selected"].error, KeyExhaustedError
                )
                empty = by_kind["batch"]
                self.assertTrue(empty.success)
                self.assertEqual(empty.pairs, ())
                self.assertEqual(signer.next_index, _LEAF_COUNT)

    def test_stale_selection_and_backward_jumps_raise_valueerror(self) -> None:
        for w in (4, 8):
            with self.subTest(w=w):
                signer = _build_signer(w)
                # Leaves remain, but the front is already past the targets.
                signer.sign_batch(tuple(f"w{w}:front-{i}" for i in range(12)))
                history = History()
                group = _ThreadGroup(self, 3)

                def stale_selection() -> None:
                    indices = (3, 7)
                    messages = (f"w{w}:old-3", f"w{w}:old-7")
                    history.execute(
                        "selected",
                        lambda: signer.sign_selected(indices, messages),
                        messages=messages,
                        indices=indices,
                    )

                def backward_jump(worker: int) -> None:
                    history.execute(
                        "advance",
                        lambda: signer.advance_to(10),
                        target=10,
                    )

                group.add("stale-selection", stale_selection)
                group.add("backward-0", lambda: backward_jump(0))
                group.add("backward-1", lambda: backward_jump(1))
                group.run()

                self.assertEqual(len(history.records), 3)
                for record in history.records:
                    self.assertFalse(record.success)
                    self.assertIsInstance(record.error, ValueError)
                    self.assertEqual(record.pairs, ())
                self.assertEqual(signer.next_index, 12)
                self.assertEqual(signer.remaining, 4)

    def test_equal_jump_returns_same_before_and_after(self) -> None:
        for w in (4, 8):
            with self.subTest(w=w):
                signer = _build_signer(w)
                signer.sign_batch(tuple(f"w{w}:front-{i}" for i in range(5)))
                history = History()
                group = _ThreadGroup(self, 2)

                def equal_jump() -> None:
                    history.execute(
                        "advance", lambda: signer.advance_to(5), target=5
                    )

                def reader() -> None:
                    history.execute("next_index", lambda: signer.next_index)

                group.add("equal-jump", equal_jump)
                group.add("reader", reader)
                group.run()

                jump = next(
                    record
                    for record in history.records
                    if record.kind == "advance"
                )
                self.assertEqual((jump.before, jump.after), (5, 5))
                self.assertEqual(signer.next_index, 5)
                self.assertEqual(signer.remaining, _LEAF_COUNT - 5)

    def test_bad_message_batch_raises_typeerror_and_consumes_nothing(self) -> None:
        for w in (4, 8):
            with self.subTest(w=w):
                signer = _build_signer(w)
                history = History()
                group = _ThreadGroup(self, 2)

                def bad_batch() -> None:
                    messages = (f"w{w}:ok-1", object(), f"w{w}:ok-3")
                    history.execute(
                        "batch",
                        lambda: signer.sign_batch(messages),
                        messages=messages,
                    )

                def good_single() -> None:
                    msg = f"w{w}:concurrent-good"
                    history.execute(
                        "sign", lambda: signer.sign(msg), messages=(msg,)
                    )

                group.add("bad-batch", bad_batch)
                group.add("good-sign", good_single)
                group.run()

                bad = next(
                    record
                    for record in history.records
                    if not record.success
                )
                self.assertIsInstance(bad.error, TypeError)
                self.assertEqual(bad.pairs, ())
                # Exactly the one good single sign spent a leaf; the rejected
                # batch neither consumed leaves nor returned partial output.
                self.assertEqual(signer.next_index, 1)
                next_signature = signer.sign(f"w{w}:after-bad-batch")
                self.assertEqual(next_signature.index, 1)
                self.assertTrue(
                    merkle_verify(
                        f"w{w}:after-bad-batch",
                        next_signature,
                        signer.public_key,
                    )
                )


if __name__ == "__main__":
    unittest.main()
