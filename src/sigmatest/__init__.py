"""sigmatest - lint and unit-test Sigma detection rules against sample events."""

from sigmatest.errors import SampleError, SigmaTestError, UnsupportedSigmaError
from sigmatest.linter import LintProblem, lint_rule
from sigmatest.matcher import Rule, load_rule, rule_fires
from sigmatest.runner import RuleResult, SampleOutcome, run_rule

__version__ = "0.1.0"

__all__ = [
    "LintProblem",
    "Rule",
    "RuleResult",
    "SampleError",
    "SampleOutcome",
    "SigmaTestError",
    "UnsupportedSigmaError",
    "__version__",
    "lint_rule",
    "load_rule",
    "rule_fires",
    "run_rule",
]
