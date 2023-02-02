# define interface for query which is asserted by mypy as well as runtime checking

from typing import Protocol, runtime_checkable


@runtime_checkable
class Query(Protocol):
    """Query service interface"""

    name: str
    description: str

    def execute(self, ctx: dict) -> dict:
        """execute() uses a generic ctx dict to pass in all parameters"""
        return {}


@runtime_checkable
class Process(Protocol):
    """Process service interface"""

    name: str
    description: str

    def update(self, payload: dict) -> dict:
        return {}

    def payload(self, ctx: dict) -> dict:
        """execute() uses a generic ctx dict to pass in all parameters"""
        return {}

    def execute(self, ctx: dict) -> dict:
        """execute() uses a generic ctx dict to pass in all parameters"""
        return {}
