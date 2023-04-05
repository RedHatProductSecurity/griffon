import inspect
from datetime import datetime
from enum import Enum
from itertools import chain
from types import ModuleType
from typing import Callable, Optional, Union, get_args, get_origin

import click
from osidb_bindings.bindings.python_client.types import OSIDBModel

from griffon import get_config_option


def abort_if_false(ctx, param, value: bool):
    """Helper callback for aborting the command if confirmation check fails"""
    if not value:
        ctx.abort()


def multivalue_params_to_csv(params: dict) -> dict:
    """
    convert multivalue params represented as tuples or lists
    into csv string
    """
    for param_name, param_value in params.items():
        if isinstance(param_value, (tuple, list)):
            params[param_name] = ",".join(params[param_name])
    return params


def safe_issubclass(cls: type, class_or_tuple):
    """Safe variant of issubclass which checks for first argument being a class"""
    return inspect.isclass(cls) and issubclass(cls, class_or_tuple)


def to_option_type(type_):
    """Convert type to the Click option type"""

    is_multiple = False
    if get_origin(type_) is list:
        option_type = get_args(type_)[0]
        is_multiple = True
    elif get_origin(type_) == Union and all(safe_issubclass(arg, Enum) for arg in get_args(type_)):
        option_type = click.Choice(
            list(chain.from_iterable([list(enum) for enum in get_args(type_)]))
        )
    elif safe_issubclass(type_, Enum):
        option_type = click.Choice(list(type_))
    elif type_ is datetime:
        option_type = click.DateTime()
    else:
        option_type = type_

    return option_type, is_multiple


def filter_request_fields(fields: dict, exclude: list[str]):
    keep = {}
    for field, field_type in fields.items():
        # Filter out related models
        if safe_issubclass(field_type, OSIDBModel) or (
            get_origin(field_type) is list and safe_issubclass(get_args(field_type)[0], OSIDBModel)
        ):
            continue

        # Filter out excluded fields
        if field in exclude:
            continue

        keep[field] = field_type

    return keep


def get_editor():
    return get_config_option("default", "editor", "vi")


def query_params_options(
    entity: str, endpoint_module: ModuleType, options_overrides: Optional[dict[dict]] = None
) -> Callable:
    """
    Decorator which obtains all query parameters from the given endpoint module and adds
    them as `click.option` with respective type

    Type handling:
        basic types (std, int, bool, etc.) - native
        enums - via `click.Choice`
        lists - multiple option

    For each param option, variable, type, help and multiple can be overriden via
    `options_overrides`
    """
    if options_overrides is None:
        options_overrides = {}

    def inner(fn):
        wrapper = fn
        for query_param, param_type in endpoint_module.QUERY_PARAMS.items():
            option_type, is_multiple = to_option_type(param_type)
            option_params = {
                "option": f"--{query_param.replace('_','-')}",
                "variable": query_param,
                "type": option_type,
                "help": f"{entity.capitalize()} {query_param.replace('_',' ')}",
                "multiple": is_multiple,
            }
            option_override = options_overrides.get(query_param, {})
            option_params.update(
                (override, option_override[override])
                for override in option_params.keys() & option_override.keys()
            )
            wrapper = (
                click.option(
                    option_params.pop("option"), option_params.pop("variable"), **option_params
                )
            )(wrapper)
        return wrapper

    return inner


def request_body_options(
    endpoint_module: ModuleType, exclude: Optional[list[str]] = None
) -> Callable:
    """
    Decorator which obtains all request body fields from the given endpoint module
    them as `click.option` with respective type

    Type handling:
        basic types (std, int, bool, etc.) - native
        enums - via `click.Choice`
        lists - multiple option

    List of the excluded fields may be supplied
    """
    if exclude is None:
        exclude = []

    def inner(fn):
        wrapper = fn

        request_body_type = getattr(endpoint_module, "REQUEST_BODY_TYPE", None)
        if request_body_type is None:
            return wrapper

        fields = filter_request_fields(request_body_type.get_fields(), exclude=exclude)
        for field, field_type in fields.items():
            option_type, is_multiple = to_option_type(field_type)
            option_params = {
                "option": f"--{field.replace('_','-')}",
                "variable": field,
                "type": option_type,
                "help": f"{request_body_type.__name__} {field.replace('_',' ')}",
                "multiple": is_multiple,
            }

            wrapper = (
                click.option(
                    option_params.pop("option"), option_params.pop("variable"), **option_params
                )
            )(wrapper)
        return wrapper

    return inner
