"""The bisection game prototype (tools/design/bisection_game.py) on the tiny model's real traces:
it names the step dispute.first_fault names, by Merkle openings and claims alone, and a side
that stops answering loses by default."""
import functools
import math

import pytest

from tdcc_exact.backend import SkipLayer
from tdcc_exact.commit import provider_key
from tdcc_exact.dispute import bisect, first_fault
from tdcc_exact.oracle import layers_of, new_job, run_job, tiny_model
from tools.design.bisection_game import (CHALLENGER, END, PROVIDER, BisectionGame, TracePlayer,
                                         play, step_claim)

EVERY = 512
BIND = provider_key("A")


@pytest.fixture(scope="module")
def runs():
    model = tiny_model()
    job = new_job("tiny", "Will it rain tomorrow?", "g1", every=EVERY)
    layers = layers_of(model[0])
    cheat = lambda: SkipLayer(1, layers) # noqa: E731

    @functools.lru_cache(maxsize=None)
    def window(honest: bool, lo: int, hi: int):
        r = run_job(job, "A" if honest else "B", None if honest else cheat(), every=EVERY,
                    window=(lo, hi), model=model, binding=BIND)
        return tuple(r.log.records)

    a = run_job(job, "A", every=EVERY, model=model, binding=BIND).log.checkpoints
    b = run_job(job, "B", cheat(), every=EVERY, model=model, binding=BIND).log.checkpoints
    return a, b, window


def _player(runs, honest: bool, silent_after=None):
    a, b, window = runs
    return TracePlayer(a if honest else b, functools.partial(window, honest),
                       silent_after=silent_after)


def _game(runs, provider: TracePlayer, challenger: TracePlayer, k=2):
    """A game whose executor (the one-step proof's stand-in) is an honest replay."""
    a, _, window = runs
    g = None

    def executor(step, agreed, fold):
        d, (lo, hi) = g.divergence, g.window
        if fold:
            return a[d].leaf
        honest = {r.step: step_claim(r.step, bytes.fromhex(r.chain), bytes.fromhex(r.state))
                  for r in window(True, lo, hi)}
        before = (a[d - 1].leaf if d else None) if step - 1 == lo else honest[step - 1]
        assert agreed == before, "the sides agreed on a state no honest run reaches"
        return honest.get(step, END)

    g = BisectionGame(provider.commit, challenger.commit, executor, k=k)
    return g


@pytest.mark.parametrize("k", [2, 4, 16])
def test_a_cheating_provider_loses_at_the_skipped_instruction(runs, k):
    a, b, window = runs
    g = _game(runs, _player(runs, False), _player(runs, True), k)
    r = play(g, _player(runs, False), _player(runs, True))
    d = bisect(a, b)
    f = first_fault(window(True, d.lo, d.hi), window(False, d.lo, d.hi))
    assert (r.loser, r.how) == (PROVIDER, "proof")
    assert r.divergence_index == d.index
    assert r.fault_step == f.step
    n_steps = g.window[1] - g.window[0]
    bound = 1 + math.ceil(math.log(len(a), k)) + 1 + math.ceil(math.log(n_steps, k))
    assert r.rounds <= bound, (r.rounds, bound)
    assert r.moves == 2 * r.rounds


def test_more_queries_a_round_take_fewer_rounds(runs):
    rounds = []
    for k in (2, 16):
        g = _game(runs, _player(runs, False), _player(runs, True), k)
        rounds.append(play(g, _player(runs, False), _player(runs, True)).rounds)
    assert rounds[1] < rounds[0]


def test_a_cheating_challenger_loses_to_an_honest_provider(runs):
    g = _game(runs, _player(runs, True), _player(runs, False))
    r = play(g, _player(runs, True), _player(runs, False))
    assert (r.winner, r.loser, r.how) == (PROVIDER, CHALLENGER, "proof")


def test_a_challenge_with_the_same_trace_shows_no_difference(runs):
    g = _game(runs, _player(runs, True), _player(runs, True))
    r = play(g, _player(runs, True), _player(runs, True))
    assert (r.loser, r.how, r.rounds) == (CHALLENGER, "no-difference", 1)


@pytest.mark.parametrize("silent", [PROVIDER, CHALLENGER])
def test_a_side_that_stops_answering_loses_by_default(runs, silent):
    p = _player(runs, False, silent_after=2 if silent == PROVIDER else None)
    c = _player(runs, True, silent_after=2 if silent == CHALLENGER else None)
    g = _game(runs, p, c)
    r = play(g, p, c)
    assert (r.loser, r.how) == (silent, "timeout")
    assert r.rounds == 2


def test_moves_after_the_deadline_are_refused_and_anyone_can_time_out(runs):
    p, c = _player(runs, False), _player(runs, True)
    g = _game(runs, p, c)
    with pytest.raises(ValueError, match="not passed"):
        g.timeout(g.deadline)
    with pytest.raises(ValueError, match="deadline"):
        g.move(PROVIDER, p.answer(g), g.deadline + 1)
    g.move(CHALLENGER, c.answer(g), g.deadline)
    assert g.timeout(g.deadline + 1).loser == PROVIDER


def test_an_opening_that_does_not_match_the_committed_root_loses(runs):
    p, c = _player(runs, False), _player(runs, True)
    g = _game(runs, p, c)
    i, cp, path = p.answer(g)[0]
    forged = type(cp)(cp.step, c.cps[i].chain, c.cps[i].state)     # the honest leaf
    g.move(PROVIDER, [(i, forged, path)], 1)
    assert (g.ruling.loser, g.ruling.how) == (PROVIDER, "bad-opening")
    assert g.ruling.winner == CHALLENGER
