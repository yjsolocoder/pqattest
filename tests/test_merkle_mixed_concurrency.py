"""Concurrency regression tests for mixed MerkleSigner state operations.

One shared signer is driven concurrently by ``sign``, ``sign_batch``,
``sign_selected``, ``advance_to`` and ``checkpoint`` calls. Every call is
recorded with its start, its end and its return value or exception, and the
whole history is then checked against the one-time-leaf semantics: there
must exist a serial order of the recorded calls — respecting real time (a
finished call precedes any call that started after it ended) — that
reproduces every observed outcome and the final state. Snapshots taken
mid-race must restore, via ``from_checkpoint``, to exactly the state the
legal order assigns them, and failure calls must appear in that order
without changing the state or returning partial signatures.
"""

from __future__ import annotations

import hashlib
import threading
import unittest

from pqattest import (
    KeyExhaustedError,
    MerkleSignature,
    MerkleSigner,
    merkle_verify,
)

# Offset of the 2-byte big-endian ``next_index`` inside the documented v1
# checkpoint layout (8-byte magic, version, w, height, then the index).
_CHECKPOINT_NEXT_INDEX_OFFSET = 11


class _Op:
    """One recorded call: kind, arguments, start/end ticks and outcome."""

    __slots__ = ("seq", "kind", "detail", "start", "end", "outcome")

    def __init__(self, seq, kind, detail, start, end, outcome):
        self.seq = seq
        self.kind = kind
        self.detail = detail
        self.start = start
        self.end = end
        # ``("value", result)`` or ``("error", ExceptionClass)``.
        self.outcome = outcome

    def describe(self):
        kind, payload = self.outcome
        if kind == "error":
            result = f"raised {payload.__name__}"
        elif self.kind == "checkpoint":
            index = int.from_bytes(
                payload[
                    _CHECKPOINT_NEXT_INDEX_OFFSET : _CHECKPOINT_NEXT_INDEX_OFFSET + 2
                ],
                "big",
            )
            result = f"checkpoint(next_index={index})"
        elif self.kind == "advance_to":
            result = f"(before, after)={payload}"
        elif self.kind == "sign":
            result = f"index={payload.index}"
        else:
            result = f"indices={[signature.index for signature in payload]}"
        return (
            f"#{self.seq} {self.kind} [{self.start}->{self.end}] {result}"
        )


class _Recorder:
    """Thread-safe log of every call made against the shared signer."""

    def __init__(self):
        self._lock = threading.Lock()
        self._tick = 0
        self.ops = []

    def run(self, kind, detail, call):
        """Execute ``call`` and record its start, end and outcome.

        The expected failure modes of the exercised entries
        (:class:`KeyExhaustedError`, ``ValueError``, ``TypeError``) are
        recorded as the call's outcome; any other exception propagates and
        fails the test through the worker wrapper.
        """
        with self._lock:
            self._tick += 1
            start = self._tick
        try:
            value = call()
        except (KeyExhaustedError, ValueError, TypeError) as exc:
            outcome = ("error", type(exc))
        else:
            outcome = ("value", value)
        with self._lock:
            self._tick += 1
            end = self._tick
            self.ops.append(_Op(self._tick, kind, detail, start, end, outcome))


class _Model:
    """The reference one-time-leaf state machine: just ``next_index``."""

    __slots__ = ("next_index",)

    def __init__(self):
        self.next_index = 0


def _apply(model, op, leaf_count):
    """Predict ``op``'s outcome at ``model`` and advance it on success.

    Mirrors the documented semantics of each entry: a successful single
    sign consumes the current leaf, a batch consumes consecutive leaves
    atomically, an explicit selection advances to one past its last index
    (voiding the gaps), ``advance_to`` only moves forward, and a failed
    call changes nothing.
    """
    if op.kind == "sign":
        if model.next_index >= leaf_count:
            return ("error", KeyExhaustedError)
        index = model.next_index
        model.next_index += 1
        return ("value", ("sign", index))
    if op.kind == "sign_batch":
        base = model.next_index
        indices = []
        for offset, message in enumerate(op.detail):
            index = base + offset
            if index >= leaf_count:
                return ("error", KeyExhaustedError)
            if not isinstance(message, (bytes, bytearray, str)):
                return ("error", TypeError)
            indices.append(index)
        model.next_index = base + len(indices)
        return ("value", ("indices", tuple(indices)))
    if op.kind == "sign_selected":
        indices, _ = op.detail
        if model.next_index >= leaf_count:
            return ("error", KeyExhaustedError)
        if indices[0] < model.next_index or indices[-1] >= leaf_count:
            return ("error", ValueError)
        model.next_index = indices[-1] + 1
        return ("value", ("indices", indices))
    if op.kind == "advance_to":
        target = op.detail
        if target < model.next_index or target > leaf_count:
            return ("error", ValueError)
        before = model.next_index
        model.next_index = target
        return ("value", ("advance", (before, target)))
    if op.kind == "checkpoint":
        return ("value", ("checkpoint", model.next_index))
    raise AssertionError(f"unknown op kind: {op.kind}")


def _matches(predicted, op):
    """Whether the recorded outcome equals the model's prediction."""
    predicted_kind, predicted_payload = predicted
    observed_kind, observed_payload = op.outcome
    if predicted_kind == "error":
        return observed_kind == "error" and observed_payload is predicted_payload
    if observed_kind != "value":
        return False
    tag = predicted_payload[0]
    if tag == "sign":
        return (
            isinstance(observed_payload, MerkleSignature)
            and observed_payload.index == predicted_payload[1]
        )
    if tag == "indices":
        return (
            isinstance(observed_payload, tuple)
            and all(
                isinstance(signature, MerkleSignature)
                for signature in observed_payload
            )
            and tuple(signature.index for signature in observed_payload)
            == predicted_payload[1]
        )
    if tag == "advance":
        return observed_payload == predicted_payload[1]
    if tag == "checkpoint":
        return (
            isinstance(observed_payload, bytes)
            and int.from_bytes(
                observed_payload[
                    _CHECKPOINT_NEXT_INDEX_OFFSET : _CHECKPOINT_NEXT_INDEX_OFFSET + 2
                ],
                "big",
            )
            == predicted_payload[1]
        )
    raise AssertionError(f"unknown prediction tag: {tag}")


def _find_legal_order(ops, leaf_count):
    """A serial order reproducing every recorded outcome, or ``None``.

    Searches the linear extensions of the real-time order (a call that
    ended before another started must come first) for one whose replay
    against the reference model yields exactly the recorded outcomes.
    """
    count = len(ops)
    predecessors = [set() for _ in range(count)]
    for later in range(count):
        for earlier in range(count):
            if earlier != later and ops[earlier].end <= ops[later].start:
                predecessors[later].add(earlier)
    model = _Model()
    placed = []
    placed_set = set()
    dead_ends = set()

    def dfs():
        if len(placed) == count:
            return True
        state_key = (model.next_index, frozenset(placed_set))
        if state_key in dead_ends:
            return False
        for candidate in range(count):
            if candidate in placed_set:
                continue
            if not predecessors[candidate] <= placed_set:
                continue
            snapshot = model.next_index
            predicted = _apply(model, ops[candidate], leaf_count)
            if _matches(predicted, ops[candidate]):
                placed.append(candidate)
                placed_set.add(candidate)
                if dfs():
                    return True
                placed.pop()
                placed_set.discard(candidate)
            model.next_index = snapshot
        dead_ends.add(state_key)
        return False

    if not dfs():
        return None
    return list(placed)


def _replay_states(order, ops, leaf_count):
    """Replay the legal order; return (state after each op, final state)."""
    model = _Model()
    states = {}
    for position in order:
        _apply(model, ops[position], leaf_count)
        states[position] = model.next_index
    return states, model.next_index


class MixedConcurrencyTest(unittest.TestCase):
    def _run_threads(self, workers):
        barrier = threading.Barrier(len(workers))
        errors = []
        errors_lock = threading.Lock()

        def wrap(worker):
            def run():
                try:
                    barrier.wait(timeout=10)
                    worker()
                except Exception as exc:  # pragma: no cover - failure path
                    with errors_lock:
                        errors.append(exc)

            return run

        threads = [threading.Thread(target=wrap(worker)) for worker in workers]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        for thread in threads:
            self.assertFalse(thread.is_alive(), "a worker thread did not finish")
        self.assertEqual(errors, [])

    def _run_round(self, *, w, height, round_no):
        leaf_count = 1 << height
        # A reproducible public test key: fixed seed per (w, height, round).
        seed = hashlib.sha256(
            b"pqattest/mixed-concurrency/" + bytes((w, height, round_no))
        ).digest()
        signer = MerkleSigner.from_seed(seed, height=height, w=w)
        recorder = _Recorder()
        run = recorder.run

        def message(tag):
            return f"r{round_no}:{tag}".encode("utf-8")

        # Phase A: continuous batches, gapped explicit selections, leaf
        # skipping and snapshots race against plain single signs.
        def singles():
            for k in range(3):
                run("sign", message(f"single-{k}"), lambda k=k: signer.sign(
                    message(f"single-{k}")
                ))

        def batches():
            run(
                "sign_batch",
                (message("batch-0a"), message("batch-0b")),
                lambda: signer.sign_batch((message("batch-0a"), message("batch-0b"))),
            )
            run(
                "sign_batch",
                (message("batch-1a"), message("batch-1b")),
                lambda: signer.sign_batch((message("batch-1a"), message("batch-1b"))),
            )
            # An empty batch returns an empty tuple and consumes nothing.
            run("sign_batch", (), lambda: signer.sign_batch(()))
            # Valid arguments but more messages than leaves exist at all:
            # always KeyExhaustedError, never a partial consumption.
            oversized = tuple(message(f"too-many-{i}") for i in range(leaf_count + 1))
            run("sign_batch", oversized, lambda: signer.sign_batch(oversized))
            # An illegal message member: TypeError and no leaf consumed.
            bad = (message("bad-ok"), 123)
            run("sign_batch", bad, lambda: signer.sign_batch(bad))

        def selected():
            # A gapped explicit selection anchored at a freshly read index:
            # it usually succeeds and voids the gap, but may lose the race
            # and be rejected with ValueError instead.
            base = signer.next_index
            indices = (base, base + 2)
            messages = (message("selected-0"), message("selected-1"))
            run(
                "sign_selected",
                (indices, messages),
                lambda: signer.sign_selected(indices, messages),
            )

        def advances():
            target = signer.next_index + 2
            run("advance_to", target, lambda: signer.advance_to(target))
            equal = signer.next_index
            run("advance_to", equal, lambda: signer.advance_to(equal))
            run("checkpoint", None, signer.checkpoint)

        def snapshots():
            run("checkpoint", None, signer.checkpoint)
            run("checkpoint", None, signer.checkpoint)

        self._run_threads([singles, batches, selected, advances, snapshots])

        # The phase-A consumption is provably bounded (single signs and the
        # two small batches consume at most 7 leaves; the selection and the
        # forward jump can only leap past states those could have produced),
        # so the signer is neither fresh nor exhausted here.
        self.assertGreaterEqual(signer.next_index, 1)
        self.assertLessEqual(signer.next_index, leaf_count - 4)

        # Phase B: calls built on a stale index race a live batch — the
        # selection lags the current index and the jump target regresses,
        # so both must raise ValueError without touching the state.
        stale = signer.next_index - 1
        stale_selected_messages = (message("stale-selected"),)

        def stale_selection():
            run(
                "sign_selected",
                ((stale,), stale_selected_messages),
                lambda: signer.sign_selected((stale,), stale_selected_messages),
            )

        def stale_advance():
            run("advance_to", stale, lambda: signer.advance_to(stale))

        def live_batch():
            messages = (message("live-0"), message("live-1"))
            run("sign_batch", messages, lambda: signer.sign_batch(messages))

        def live_snapshot():
            run("checkpoint", None, signer.checkpoint)

        self._run_threads([stale_selection, stale_advance, live_batch, live_snapshot])

        # Phase C: drain the remaining leaves one sign at a time (recorded
        # like every other call), then exercise the exhausted signer
        # concurrently.
        drained = 0
        while True:
            run(
                "sign",
                message(f"drain-{drained}"),
                lambda drained=drained: signer.sign(message(f"drain-{drained}")),
            )
            drained += 1
            if recorder.ops[-1].outcome == ("error", KeyExhaustedError):
                break

        exhausted_selected_messages = (message("exhausted-selected"),)

        def exhausted_sign():
            run("sign", message("exhausted-sign"), lambda: signer.sign(
                message("exhausted-sign")
            ))

        def exhausted_selection():
            # A legal, non-empty selection on an exhausted signer.
            run(
                "sign_selected",
                ((0,), exhausted_selected_messages),
                lambda: signer.sign_selected((0,), exhausted_selected_messages),
            )

        def exhausted_empty_batch():
            run("sign_batch", (), lambda: signer.sign_batch(()))

        def exhausted_equal_advance():
            run("advance_to", leaf_count, lambda: signer.advance_to(leaf_count))

        def exhausted_snapshot():
            run("checkpoint", None, signer.checkpoint)

        self._run_threads(
            [
                exhausted_sign,
                exhausted_selection,
                exhausted_empty_batch,
                exhausted_equal_advance,
                exhausted_snapshot,
            ]
        )

        # The whole recorded history must be explainable by one legal
        # serial order that respects real time.
        order = _find_legal_order(recorder.ops, leaf_count)
        self.assertIsNotNone(
            order,
            "no legal serial order explains the recorded history:\n"
            + "\n".join(op.describe() for op in recorder.ops),
        )
        states, final_next_index = _replay_states(order, recorder.ops, leaf_count)

        # Every returned signature verifies against its own message, and no
        # leaf index was ever handed out twice.
        signed_pairs = []
        for op in recorder.ops:
            if op.outcome[0] != "value":
                continue
            if op.kind == "sign":
                signed_pairs.append((op.detail, op.outcome[1]))
            elif op.kind == "sign_batch":
                signed_pairs.extend(zip(op.detail, op.outcome[1]))
            elif op.kind == "sign_selected":
                signed_pairs.extend(zip(op.detail[1], op.outcome[1]))
        self.assertTrue(signed_pairs)
        for signed_message, signature in signed_pairs:
            self.assertTrue(
                merkle_verify(signed_message, signature, signer.public_key),
                f"signature for {signed_message!r} at leaf {signature.index} "
                "does not verify",
            )
        used_indices = [signature.index for _, signature in signed_pairs]
        self.assertEqual(
            len(used_indices),
            len(set(used_indices)),
            f"a leaf index was signed with twice: {sorted(used_indices)}",
        )

        # Every snapshot restores, in isolation, to exactly the state the
        # legal order assigns it, and a resumed signer spends the saved
        # next leaf.
        for position, op in enumerate(recorder.ops):
            if op.kind != "checkpoint":
                continue
            restored = MerkleSigner.from_checkpoint(op.outcome[1])
            expected = states[position]
            self.assertEqual(restored.public_key, signer.public_key)
            self.assertEqual(restored.next_index, expected)
            self.assertEqual(restored.remaining, leaf_count - expected)
            if expected < leaf_count:
                follow_up = restored.sign(message(f"resume-{position}"))
                self.assertEqual(follow_up.index, expected)
                self.assertTrue(
                    merkle_verify(
                        message(f"resume-{position}"),
                        follow_up,
                        restored.public_key,
                    )
                )
            else:
                with self.assertRaises(KeyExhaustedError):
                    restored.sign(message(f"resume-{position}"))

        # The final state agrees with the same legal order — the round
        # drained the signer to exhaustion.
        self.assertEqual(final_next_index, leaf_count)
        self.assertEqual(signer.next_index, final_next_index)
        self.assertEqual(signer.remaining, leaf_count - final_next_index)

    def test_mixed_operations_w4(self):
        for round_no in range(3):
            with self.subTest(w=4, round=round_no):
                self._run_round(w=4, height=4, round_no=round_no)

    def test_mixed_operations_w8(self):
        for round_no in range(3):
            with self.subTest(w=8, height=4, round_no=round_no):
                self._run_round(w=8, height=4, round_no=round_no)


if __name__ == "__main__":
    unittest.main()
