# Tiers fixture: 02 Appendix A probe 3 / 01 E1 (tools/parity/make_fixture.py scenario; synthetic data only).
#
# Six identical functions per side, func_N in the main database against sub_XXXXXX in the diff database,
# at different addresses, same processor. run_heuristics_for_category("Best") runs its list back to
# front (jkutils/threads.py:40 targets.pop()), so "Equal assembly or pseudo-code" (HEURISTICS[10])
# claims every pair as `Equal assembly` before "Same order and hash" (HEURISTICS[1]) gets a turn; the
# Partial category then runs nothing ("All functions matched in at least one database, finishing.").
# gen_tiers_fixtures.py also records capture_forward/ with the list run front to back (the negative
# control): every pair is then `Same order and hash`.
#
# Regenerate: python -B tests/diff/fixtures/tiers/gen_tiers_fixtures.py --only probe3 --diaphora-dir <diaphora-ref>

MAIN = {"functions": [Function(I, "func_%d" % I, 0x401000 + I * 0x100, 4) for I in range(1, 7)]}
DIFF = {"functions": [Function(I, "sub_%X" % (0x501000 + I * 0x100), 0x501000 + I * 0x100, 4) for I in range(1, 7)]}
