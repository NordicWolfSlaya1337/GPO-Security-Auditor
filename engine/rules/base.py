from abc import ABC, abstractmethod
from typing import Generator

from engine.models import GPO, Finding

_RULE_REGISTRY: list = []


def register_rule(cls):
    _RULE_REGISTRY.append(cls)
    return cls


def get_all_rules():
    return [cls() for cls in _RULE_REGISTRY]


class AuditRule(ABC):
    @property
    @abstractmethod
    def rule_id_prefix(self) -> str:
        ...

    @property
    @abstractmethod
    def category(self) -> str:
        ...

    @abstractmethod
    def evaluate(self, gpo: GPO, all_gpos: list) -> Generator[Finding, None, None]:
        ...
