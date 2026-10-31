"""The parameters, the token pools and the clock of a funnel run.

The orchestrator owns the stop. The run stops new work at the stop level:
``stop_fraction`` of the token ceiling C (the spendable budget S) or of the
wall clock W. Each phase has a pool, a share of S:

| Pool | Share | Work |
| --- | --- | --- |
| rating | 0.05 | phase 1: the model rates unit cards |
| unit_check | 0.25 | phase 2: one call for each unit |
| triage | 0.08 | one blind verification call for each new lead |
| deep_check | 0.50 | phase 3: deep-check agent sessions |
| verify | 0.05 | phase 4: one blind call for each finding |
| reserve | 0.07 | more unit checks, then more deep checks |

The free-roaming session has its own pool, outside these shares: its cap is
``free_token_fraction`` of the ceiling (0.6, so the token reserve of the
agent runner stops its first turn at 45% of the ceiling). Its use counts in
the global rule as it grows, and the global rule keeps
``free_headroom_fraction`` of the ceiling (at most the rest of its cap) for
its next calls.

A pool is a soft limit: a task starts only when its pool has room for its
estimate. The global rule is hard: the used tokens, the estimates of the
running calls, the rest of the cap of each running agent session and the
unused part of the verify pool stay at or below S. Thus a call that starts
can always end below S, and the verification of the last findings always has
its tokens. ``move`` gives the unused tokens of one pool to another (the
roll-forward rules of the orchestrator); each move is recorded.

The defaults are the measured values of funnel version 1.4: one pass, at
most 6 findings for a run and 2 for each file.
"""

from __future__ import annotations

import dataclasses
import time
from dataclasses import dataclass
from typing import Any, Callable

# The pool of the free-roaming session: outside the shares of the spendable budget.
FREE_POOL = "free"
# The pools whose unused part the global rule keeps for their own tasks.
PROTECTED_POOLS = ("verify",)
# The parameters that can be null.
OPTIONAL_NUMBERS = frozenset({"call_temperature"})


@dataclass(frozen=True)
class Parameters:
    """Each value that changes what a funnel run does. ``record`` gives them for the run record."""

    # Stop level: the share of the token ceiling and of the wall clock.
    stop_fraction: float = 0.90
    # The free-roaming session: the single agent on the whole repository,
    # with this share of the token ceiling (its own pool) and the wall clock
    # less a margin (the larger of the two values). The global rule keeps
    # free_headroom_fraction of the ceiling for its next calls.
    free_token_fraction: float = 0.6
    free_headroom_fraction: float = 0.15
    free_time_margin_fraction: float = 0.15
    free_time_margin_min_seconds: int = 1800
    # A large repository: more than large_repo_files files, or a queue that
    # phase 2 cannot check. Its free-roaming session gets
    # free_token_fraction_large of the ceiling, and its triage pool
    # share_triage_large of S (from the reserve), so that each lead gets its
    # triage call.
    large_repo_files: int = 1000
    free_token_fraction_large: float = 0.2
    share_triage_large: float = 0.11
    # Phase 0: the inventory, at most min(phase0_max_seconds,
    # phase0_fraction x W), and a grace for the process to end.
    phase0_fraction: float = 0.10
    phase0_max_seconds: int = 1500
    phase0_grace_seconds: int = 120
    max_units: int = 5000
    inventory_limit_bytes: int = 8 << 20
    # Phase 1, the rating: on. The rank of a unit is 0.6 x rating + 0.4 x
    # the deterministic score. One parameter switches it off; then its share
    # goes to the unit checks.
    use_rating: bool = True
    # The pool shares of the spendable budget S.
    share_rating: float = 0.05
    share_unit_check: float = 0.25
    share_triage: float = 0.08
    share_deep_check: float = 0.50
    share_verify: float = 0.05
    share_reserve: float = 0.07
    # Concurrency: model calls and agent sessions at the same time (each
    # agent session counts as one). The model gateway also admits at most 8
    # upstream requests at the same time.
    max_concurrency: int = 8
    max_workers: int = 4
    rating_batch: int = 30
    rating_weight: float = 0.6
    rating_unrated_score: float = 2.5
    # Phase 2: at most max_unit_checks unit checks in a run (the reserve
    # included), so that time and tokens remain for the deep checks.
    max_unit_checks: int = 1500
    # A large queue (phase 2 cannot check each unit): the deep-check pool
    # gives deep_pace_start of its tokens at the start and the rest with the
    # progress of phase 2, so that the deep checks run during the whole run
    # and take the best triaged units (1.0: no pacing).
    deep_pace_start: float = 0.25
    # Phase 2: the slice of one unit.
    slice_max_chars: int = 40_000
    header_lines: int = 40
    # Phase 3: one deep-check session for each unit with leads. A session
    # starts only when worker_seconds remain before the work cut-off.
    worker_tokens: int = 250_000
    worker_seconds: int = 900
    # Phase 4: the blind verification of at most this many output
    # candidates, in rank order. Its score ranks; it drops nothing.
    verify_max_findings: int = 60
    # Search hits: each match of a grep search of an agent session (the
    # free-roaming session and the deep checks) and each file of a find
    # search adds to the queue score of the unit around it, or adds a window
    # of +-hit_window_lines lines when no unit holds the line. Only the first
    # hit_rank_limit matches of each search count; the first hit_top_rank
    # get hit_bonus_top, the others hit_bonus; a find file gets
    # hit_bonus_find for its best unit. A unit gets at most hit_bonus_cap,
    # and a run adds at most hit_max_windows windows.
    hit_rank_limit: int = 30
    hit_top_rank: int = 10
    hit_bonus_top: float = 0.5
    hit_bonus: float = 0.25
    hit_bonus_find: float = 0.15
    hit_bonus_cap: float = 0.75
    hit_window_lines: int = 20
    hit_window_base: float = 0.3
    hit_max_windows: int = 300
    # Roll-forward: after each window of unit checks, a lead rate below this
    # value moves half of the free deep-check tokens to the unit checks.
    low_lead_rate: float = 0.05
    low_rate_window: int = 50
    # Output rules: one ranked list, the free-roaming findings first, then
    # the deep-check findings; at most max_findings_total findings for the
    # run and max_findings_per_file for each file.
    max_locations: int = 4
    max_findings_per_file: int = 2
    max_findings_total: int = 6
    # More output slots, for the run and for each file, that only a finding
    # with the majority verdict "exploitable" of its verifications can take.
    extra_findings_total: int = 0
    extra_findings_per_file: int = 0
    dedup_radius_lines: int = 10
    max_location_lines: int = 84
    resolve_window_lines: int = 30
    # Direct model calls: the sampling of the agent sessions (the agent
    # sends temperature 1.0 with each call). None sends no temperature.
    call_temperature: float | None = 1.0
    call_timeout_seconds: int = 780
    call_attempts: int = 4
    # Token estimates of a call before it starts (the answer, reasoning included).
    estimate_answer_tokens: int = 4_000
    # Time: no new phase-2 or phase-3 work in the last work_margin_seconds
    # before the stop; verification calls go on until verify_margin_seconds
    # before the stop.
    work_margin_seconds: int = 600
    verify_margin_seconds: int = 120
    # A budget of more than one standard run (budget.funnel_parameters).
    # The blind verifications of each finding: the verdict is the majority,
    # the score the mean. With depth_passes, when the unit queue and the
    # leads are done, the run starts focus sessions (agent sessions on the
    # whole repository, one weakness family each, focus_tokens each), then
    # the sweep (deep checks of the checked units without a lead, in queue
    # order), while the budget and the time allow.
    verify_votes: int = 1
    depth_passes: bool = False
    focus_tokens: int = 0

    def record(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_record(cls, values: dict[str, Any]) -> Parameters:
        """The parameters of a record; an unknown key or a wrong type is an error."""
        names = {item.name: item for item in dataclasses.fields(cls)}
        unknown = sorted(set(values) - set(names))
        if unknown:
            raise ValueError(f"unknown funnel parameters: {', '.join(unknown)}")
        converted: dict[str, Any] = {}
        for name, value in values.items():
            default = getattr(cls, name)
            if name in OPTIONAL_NUMBERS:
                if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float))):
                    raise ValueError(f"funnel parameter {name} must be a number or null")
                converted[name] = None if value is None else float(value)
                continue
            if isinstance(default, bool):
                if not isinstance(value, bool):
                    raise ValueError(f"funnel parameter {name} must be true or false")
            elif isinstance(default, int):
                if isinstance(value, bool) or not isinstance(value, int):
                    raise ValueError(f"funnel parameter {name} must be an integer")
            elif isinstance(default, float):
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise ValueError(f"funnel parameter {name} must be a number")
                value = float(value)
            converted[name] = value
        parameters = cls(**converted)
        parameters.check()
        return parameters

    def shares(self) -> dict[str, float]:
        """The pool shares; without the rating phase its share goes to the unit checks."""
        return {
            "rating": self.share_rating if self.use_rating else 0.0,
            "unit_check": self.share_unit_check + (0.0 if self.use_rating else self.share_rating),
            "triage": self.share_triage,
            "deep_check": self.share_deep_check,
            "verify": self.share_verify,
            "reserve": self.share_reserve,
        }

    def check(self) -> None:
        problems = []
        if not 0 < self.stop_fraction <= 1:
            problems.append("stop_fraction must be in (0, 1]")
        if abs(sum(self.shares().values()) - 1.0) > 1e-9 or min(self.shares().values()) < 0:
            problems.append("the pool shares must be positive and sum to 1")
        if not 0 <= self.free_token_fraction < 1 or not 0 <= self.free_headroom_fraction <= 1:
            problems.append("free_token_fraction must be in [0, 1) and free_headroom_fraction in [0, 1]")
        if not 0 <= self.free_token_fraction_large < 1 or not 0 <= self.share_triage_large < 1 or self.large_repo_files < 0:
            problems.append("free_token_fraction_large and share_triage_large must be in [0, 1), large_repo_files not negative")
        if self.max_concurrency < 2 or not 1 <= self.max_workers < self.max_concurrency:
            problems.append("max_concurrency must be 2 or more, and max_workers from 1 to max_concurrency - 1")
        if self.max_locations < 1 or self.max_findings_total < 1 or self.max_findings_per_file < 1:
            problems.append("the output caps must be positive")
        if self.extra_findings_total < 0 or self.extra_findings_per_file < 0:
            problems.append("the extra output slots must not be negative")
        if self.verify_votes < 1 or self.focus_tokens < 0:
            problems.append("verify_votes must be positive and focus_tokens not negative")
        if self.verify_max_findings < 0:
            problems.append("verify_max_findings must not be negative")
        if self.max_unit_checks < 1 or not 0 < self.deep_pace_start <= 1:
            problems.append("max_unit_checks must be positive and deep_pace_start in (0, 1]")
        if self.rating_batch < 1 or not 0 <= self.rating_weight <= 1:
            problems.append("rating_batch must be positive and rating_weight in [0, 1]")
        if self.call_temperature is not None and not 0 <= self.call_temperature <= 2:
            problems.append("call_temperature must be null or in [0, 2]")
        if min(self.hit_bonus_top, self.hit_bonus, self.hit_bonus_find, self.hit_bonus_cap) < 0 or self.hit_window_lines < 1:
            problems.append("the search-hit bonuses must not be negative, and hit_window_lines must be positive")
        if problems:
            raise ValueError("; ".join(problems))


DEFAULT_PARAMETERS = Parameters()


class Budget:
    """The token ledger of the orchestrator: used tokens, running estimates and the pools.

    ``used`` holds the tokens of finished calls and the polled tokens of the
    agent sessions, by pool. ``pending`` holds the estimate of each running
    task (a direct call, or the rest of the cap of an agent session) and its
    reservation: the tokens that the model gateway holds for the call in
    flight (the request size / 3 + the completion ceiling of the model). The
    pools count the estimate; the global rule counts the larger of the two,
    so the gateway does not refuse a call that the orchestrator admits.
    """

    def __init__(self, ceiling: int, parameters: Parameters = DEFAULT_PARAMETERS) -> None:
        self.ceiling = int(ceiling)
        self.parameters = parameters
        self.stop_level = int(self.ceiling * parameters.stop_fraction)
        self.initial_stop_level = self.stop_level
        self.allowance = {pool: int(self.stop_level * share) for pool, share in parameters.shares().items()}
        # The cap of the running free-roaming session (set_free_limit).
        self.free_limit = self.free_cap()
        self.allowance[FREE_POOL] = self.free_limit
        self.initial = dict(self.allowance)
        self.used = {pool: 0 for pool in self.allowance}
        # task -> (pool, estimate, counts in the pool, reservation). The rest
        # of the cap of the free-roaming session counts in the global rule
        # only: its actual use is charged to its pool as it grows.
        self.pending: dict[str, tuple[str, int, bool, int]] = {}
        self.moves: list[dict[str, Any]] = []

    def free_cap(self) -> int:
        """The token budget of the free-roaming session."""
        return int(self.ceiling * self.parameters.free_token_fraction)

    def free_pending(self, used: int) -> int:
        """The tokens that the global rule keeps for the next calls of the free-roaming session
        (``used``: the tokens of the running session)."""
        return max(0, min(self.free_limit - used, int(self.ceiling * self.parameters.free_headroom_fraction)))

    def set_free_limit(self, tokens: int) -> None:
        """The cap of the free-roaming session: its pool holds the used tokens and this cap."""
        self.free_limit = max(0, int(tokens))
        self.allowance[FREE_POOL] = self.used[FREE_POOL] + self.free_limit

    def total_used(self) -> int:
        return sum(self.used.values())

    def pending_total(self, pool: str | None = None) -> int:
        """The running tokens: of each task for the global rule (the estimate or the
        reservation, the larger), or the estimates of the tasks that count in ``pool``."""
        if pool is None:
            return sum(max(estimate, reserved) for _, estimate, _, reserved in self.pending.values())
        return sum(estimate for name, estimate, in_pool, _ in self.pending.values() if name == pool and in_pool)

    def pool_committed(self, pool: str) -> int:
        return self.used[pool] + self.pending_total(pool)

    def pool_remaining(self, pool: str) -> int:
        return self.allowance[pool] - self.pool_committed(pool)

    def protected(self, pool: str | None = None) -> int:
        """The unused part of the verify pool that a task of ``pool`` cannot take (none for a verify task)."""
        return sum(
            max(0, self.allowance[name] - self.pool_committed(name)) for name in PROTECTED_POOLS if name in self.allowance and name != pool
        )

    def committed(self) -> int:
        return self.total_used() + self.pending_total()

    def headroom(self, pool: str) -> int:
        """The tokens that a new task of ``pool`` can use under the global rule."""
        return self.stop_level - self.committed() - self.protected(pool)

    def at_stop(self) -> bool:
        """The used tokens reached the stop level."""
        return self.total_used() >= self.stop_level

    def admits(self, pool: str, estimate: int, *, pool_minimum: int | None = None, reserve: int = 0) -> bool:
        """Whether a task of ``pool`` with ``estimate`` tokens can start now.

        The pool must have room for ``pool_minimum`` tokens (default: the
        estimate); the global rule needs room for the whole estimate and for
        the reservation of the gateway (``reserve``).
        """
        if self.at_stop():
            return False
        needed = estimate if pool_minimum is None else pool_minimum
        return self.pool_remaining(pool) >= needed and self.headroom(pool) >= max(estimate, reserve)

    def start(self, task: str, pool: str, estimate: int, *, in_pool: bool = True, reserve: int = 0) -> None:
        """A task starts with ``estimate`` tokens; ``in_pool`` False counts it in the global rule only."""
        if task in self.pending:
            raise ValueError(f"task {task} is running already")
        if pool not in self.allowance:
            raise ValueError(f"unknown pool {pool}")
        self.pending[task] = (pool, max(0, int(estimate)), in_pool, max(0, int(reserve)))

    def update(self, task: str, remaining: int, *, reserve: int | None = None) -> None:
        """A new estimate of the tokens that a running task can still use (and of its reservation)."""
        if task in self.pending:
            pool, _, in_pool, reserved = self.pending[task]
            self.pending[task] = (pool, max(0, int(remaining)), in_pool, reserved if reserve is None else max(0, int(reserve)))

    def charge(self, pool: str, tokens: int) -> None:
        self.used[pool] += max(0, int(tokens))

    def finish(self, task: str, tokens: int | None = None) -> None:
        """The task ended; ``tokens`` is its use that was not charged yet."""
        entry = self.pending.pop(task, None)
        if entry is not None and tokens is not None:
            self.charge(entry[0], tokens)

    def move(self, source: str, target: str, amount: int, reason: str) -> int:
        """Give up to ``amount`` unused tokens of ``source`` to ``target``; return the tokens moved."""
        moved = max(0, min(int(amount), self.pool_remaining(source)))
        if moved:
            self.allowance[source] -= moved
            self.allowance[target] += moved
            self.moves.append({"from": source, "to": target, "tokens": moved, "reason": reason})
        return moved

    def grow(self, tokens: int, reason: str) -> int:
        """More tokens for the plan (the money that the cost cap still holds buys them): each pool gets its share."""
        tokens = max(0, int(tokens))
        if tokens:
            self.stop_level += tokens
            self.ceiling = int(self.stop_level / self.parameters.stop_fraction)
            for pool, share in self.parameters.shares().items():
                self.allowance[pool] += int(tokens * share)
            self.moves.append({"from": "money", "to": "pools", "tokens": tokens, "reason": reason})
        return tokens

    def record(self) -> dict[str, Any]:
        return {
            "ceiling": self.ceiling,
            "stop_level": self.stop_level,
            "initial_allowance": dict(self.initial),
            "allowance": dict(self.allowance),
            "used": dict(self.used),
            "total_used": self.total_used(),
            "pending": self.pending_total(),
            "moves": list(self.moves),
        }


class Clock:
    """The time limits of a run, from the start of the orchestrator.

    ``end`` is the stop level of the wall clock (``stop_fraction`` x W): the
    orchestrator ends its work there and writes its files. No new unit check
    or deep check starts after ``work_end``, and no new verification after
    ``verify_end``.
    """

    def __init__(
        self,
        wall_clock_seconds: float,
        parameters: Parameters = DEFAULT_PARAMETERS,
        *,
        clock: Callable[[], float] = time.monotonic,
        started: float | None = None,
    ) -> None:
        self.clock = clock
        self.started = clock() if started is None else started
        self.wall_clock = float(wall_clock_seconds)
        self.end = self.wall_clock * parameters.stop_fraction
        self.work_end = max(0.0, self.end - min(parameters.work_margin_seconds, self.end / 4))
        self.verify_end = max(0.0, self.end - min(parameters.verify_margin_seconds, self.end / 10))
        self.phase0_deadline = min(float(parameters.phase0_max_seconds), parameters.phase0_fraction * self.wall_clock)
        margin = max(float(parameters.free_time_margin_min_seconds), parameters.free_time_margin_fraction * self.wall_clock)
        # A short wall clock keeps half of it for the free-roaming session.
        self.free_seconds = int(self.wall_clock - margin) if self.wall_clock > 2 * margin else int(self.wall_clock / 2)

    def elapsed(self) -> float:
        return self.clock() - self.started

    def at(self, seconds: float) -> float:
        """The clock value at ``seconds`` after the start."""
        return self.started + seconds

    def past(self, seconds: float) -> bool:
        return self.elapsed() >= seconds

    def remaining(self, seconds: float) -> float:
        return seconds - self.elapsed()

    def record(self) -> dict[str, Any]:
        return {
            "wall_clock_seconds": self.wall_clock,
            "end_seconds": round(self.end, 1),
            "work_end_seconds": round(self.work_end, 1),
            "verify_end_seconds": round(self.verify_end, 1),
            "phase0_deadline_seconds": round(self.phase0_deadline, 1),
            "free_session_seconds": self.free_seconds,
        }
