"""
Helpers for direct usage or debbuging
"""
import json
from typing import Callable, Optional, Type, Union

from component_registry_bindings.bindings.python_client.types import (
    ComponentRegistryModel,
)
from osidb_bindings.bindings.python_client.types import OSIDBModel


def debug_data_dump(filename: str, data, transform_fn: Optional[Callable] = None):
    """
    Debugging utility to avoid heavy HTTP data transfers.
    Serializes the data into JSON and dumps that into a
    specified file.

    transform function can be used for postprocessing the data after
    the basic dict serialization

    """
    if isinstance(data, list):
        json_data = [
            item.to_dict() if isinstance(item, (ComponentRegistryModel, OSIDBModel)) else item
            for item in data
        ]

        if transform_fn is not None:
            json_data = list(map(transform_fn, json_data))

    else:
        json_data = data

    with open(filename, "w") as fp:
        json.dump(json_data, fp)


def debug_data_load(
    filename: str,
    model: Optional[Union[Type[ComponentRegistryModel], Type[OSIDBModel]]] = None,
    transform_fn: Optional[Callable] = None,
):
    """
    Debugging utility to avoid heavy HTTP data transfers.
    Loads the data from specified JSON file and transforms them
    back into internal models.

    transform function can be used for preprocessing the data before
    the internal model transformation
    """
    with open(filename) as fp:
        json_data = json.load(fp)

    if isinstance(json_data, list):
        if transform_fn is not None:
            json_data = list(map(transform_fn, json_data))

        data = [model.from_dict(item) for item in json_data]  # type: ignore

    else:
        data = json_data
    return data
