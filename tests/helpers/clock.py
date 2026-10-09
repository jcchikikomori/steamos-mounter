"""A deterministic stand-in for the ``context.Clock`` protocol.

Design Doc "Mock Boundary Decisions": the clock is faked so deadlines and timers
(the 120 s CLI marker, the dialog timeouts) are tested without waiting.
"""

from datetime import UTC, datetime, timedelta

DEFAULT_START = datetime(2026, 10, 8, 2, 11, 40, tzinfo=UTC)
DEFAULT_MONOTONIC = 1000.0


class FakeClock:
    """Wall clock and monotonic clock that only move when ``advance`` is called."""

    def __init__(
        self,
        start: datetime = DEFAULT_START,
        monotonic_start: float = DEFAULT_MONOTONIC,
    ) -> None:
        if start.utcoffset() is None:
            raise ValueError("FakeClock start needs a timezone (records use UTC)")
        self._now = start
        self._monotonic = monotonic_start

    def monotonic(self) -> float:
        return self._monotonic

    def now(self) -> datetime:
        return self._now

    def advance(self, seconds: float) -> None:
        """Move both clocks forward by ``seconds``."""
        if seconds < 0:
            raise ValueError(f"FakeClock cannot go backwards ({seconds} s)")
        self._monotonic += seconds
        self._now += timedelta(seconds=seconds)
