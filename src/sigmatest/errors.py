"""Exception hierarchy for sigmatest."""

from __future__ import annotations


class SigmaTestError(Exception):
    """Base class for all sigmatest errors."""


class UnsupportedSigmaError(SigmaTestError):
    """A rule uses Sigma syntax this evaluator does not implement.

    Raised (rather than silently returning False) so an un-evaluatable rule is
    never mistaken for a rule that simply didn't match - a rule the tool cannot
    reason about must not be reported as "tested".
    """


class SampleError(SigmaTestError):
    """A sample case is malformed (e.g. no event/events/burst key)."""
