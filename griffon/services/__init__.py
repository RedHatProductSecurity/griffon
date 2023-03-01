# define interface for query which is asserted by mypy as well as runtime checking
import logging
import typing
from typing import Any, Dict, List, Protocol, runtime_checkable

logger = logging.getLogger("griffon")


@runtime_checkable
class Query(Protocol):
    """Query service interface"""

    name: str
    description: str
    allowed_params: list

    def __init__(self, params: dict) -> None:
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
    allowed_params: list

    def __init__(self, params: dict) -> None:
        """Use generic params dict to pass in all parameters"""
        pass

    def update(self) -> typing.Union[dict, List[Dict[str, Any]]]:
        return {}


@runtime_checkable
class Report(Protocol):
    """Query service interface"""

    name: str
    description: str
    allowed_params: list

    def __init__(self, params: dict) -> None:
        """Use generic params dict to pass in all parameters"""
        pass

    def generate(self) -> typing.Union[dict, List[Dict[str, Any]]]:
        """execute() uses a generic ctx dict to pass in all parameters"""
        return {}


def check_allowed_params(allowed_params, params):
    """Check if params are allowed."""
    logger.debug(params)
    if allowed_params:
        for key in params.keys():
            assert key in allowed_params


class QueryService:
    def invoke(self, obj, params: dict):
        check_allowed_params(obj.allowed_params, params)
        return obj(params).execute()


class ReportService:
    def invoke(self, obj, params: dict):
        check_allowed_params(obj.allowed_params, params)
        return obj(params).generate()


class ProcessService:
    def invoke(self, obj, params: dict):
        check_allowed_params(obj.allowed_params, params)
        return obj(params).process()
