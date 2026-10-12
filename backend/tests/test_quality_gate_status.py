"""An exposed holdout can never turn a failed gate into a passed regression."""

import pytest
from scripts.evaluate_quality import evaluation_status


@pytest.mark.parametrize(
    ("gate", "regression", "subset", "expected"),
    [
        (False, True, False, "failed"),
        (False, False, False, "failed"),
        (True, True, False, "regression_passed"),
        (True, False, False, "passed"),
        (None, True, False, "baseline_measured"),
        (True, True, True, "diagnostic_subset"),
    ],
)
def test_status_preserves_failure_and_diagnostic_scope(gate, regression, subset, expected):
    assert evaluation_status(gate, regression=regression, subset=subset) == expected
