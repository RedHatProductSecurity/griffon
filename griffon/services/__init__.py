# define interface for query which is asserted by mypy as well as runtime checking
import typing
from typing import Any, Dict, List, Protocol, runtime_checkable


@runtime_checkable
class Query(Protocol):
    """Query service interface"""

    name: str
    description: str

    def __init__(self, params: dict):
        """Use generic params dict to pass in all parameters"""
        pass

    def execute(self) -> typing.Union[dict, List[Dict[str, Any]]]:
        """execute() uses a generic ctx dict to pass in all parameters"""
        return {}


@runtime_checkable
class Process(Protocol):
    """Process service interface"""

    name: str
    description: str

    def __init__(self, params: dict):
        """Use generic params dict to pass in all parameters"""
        pass

    def update(self) -> typing.Union[dict, List[Dict[str, Any]]]:
        return {}
