from dataclasses import dataclass, field
from typing import Callable, Iterable, Literal, Protocol

State = Literal["verified", "mismatch", "unknown"]
STATES = ("verified", "mismatch", "unknown")


@dataclass(frozen=True)
class Outcome:
    state: State
    reason: str
    evidence: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Case:
    case_id: str
    run: Callable[[dict], Outcome]


class Plugin(Protocol):
    def cases(self, config: dict) -> Iterable[Case]: ...
