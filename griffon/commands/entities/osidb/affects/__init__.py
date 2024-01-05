"""
osidb affect entity operations

"""
import json
import logging

import click
from osidb_bindings.bindings.python_client.api.osidb import (
    osidb_api_v1_affects_create,
    osidb_api_v1_affects_list,
    osidb_api_v1_affects_retrieve,
    osidb_api_v1_affects_update,
)
from osidb_bindings.bindings.python_client.models import Affect
from requests import HTTPError

from griffon import OSIDB_SERVER_URL, OSIDBService, progress_bar
from griffon.commands.entities.helpers import (
    abort_if_false,
    filter_request_fields,
    get_editor,
    multivalue_params_to_csv,
    query_params_options,
    request_body_options,
)
from griffon.exceptions import GriffonException
from griffon.output import console, cprint

logger = logging.getLogger("griffon")


@click.group(help=f"{OSIDB_SERVER_URL}/osidb/api/v1/affects")
@click.pass_context
def affects(ctx):
    """OSIDB Affects."""
    pass


@affects.command(name="list")
@query_params_options(
    entity="Affect",
    endpoint_module=osidb_api_v1_affects_list,
    options_overrides={
        "include_fields": {"type": click.Choice(OSIDBService.get_fields(Affect))},
        "exclude_fields": {"type": click.Choice(OSIDBService.get_fields(Affect))},
        "include_meta_attr": {"type": click.Choice(OSIDBService.get_meta_attr_fields(Affect))},
    },
)
@click.pass_context
@progress_bar()
def list_affects(ctx, **params):
    # TODO: handle pagination
    # TODO: handle output
    session = OSIDBService.create_session()

    params = multivalue_params_to_csv(params)
    return cprint(
        list(session.affects.retrieve_list_iterator_async(max_results=5000, **params)), ctx=ctx
    )


@affects.command(name="get")
@click.option("--uuid", "affect_uuid", help="Affect UUID.", required=True)
@query_params_options(
    entity="Affect",
    endpoint_module=osidb_api_v1_affects_retrieve,
    options_overrides={
        "include_fields": {"type": click.Choice(OSIDBService.get_fields(Affect))},
        "exclude_fields": {"type": click.Choice(OSIDBService.get_fields(Affect))},
        "include_meta_attr": {"type": click.Choice(OSIDBService.get_meta_attr_fields(Affect))},
    },
)
@click.pass_context
@progress_bar()
def get_affect(ctx, affect_uuid, **params):
    """
    For parameter reference see:
    <OSIDB_SERVER_URL>/osidb/api/v1/schema/swagger-ui - /osidb/api/v1/affects/{uuid}
    """
    params = multivalue_params_to_csv(params)

    session = OSIDBService.create_session()
    data = session.affects.retrieve(affect_uuid, **params)
    return cprint(data, ctx=ctx)


@affects.command(name="update")
@click.option("--uuid", "affect_uuid", help="Affect UUID.", required=True)
@request_body_options(endpoint_module=osidb_api_v1_affects_update, exclude=["uuid"])
@click.pass_context
@progress_bar()
def update_affect(ctx, affect_uuid, **params):
    request_body_type = getattr(osidb_api_v1_affects_update, "REQUEST_BODY_TYPE", None)
    if request_body_type is None:
        raise GriffonException(
            "No request body template for Affect update. "
            "Is correct version of osidb-bindings installed?"
        )

    fields = filter_request_fields(request_body_type.get_fields(), exclude=["uuid"])
    params = multivalue_params_to_csv(params)

    session = OSIDBService.create_session()

    try:
        data = session.affects.retrieve(id=affect_uuid, include_fields=",".join(fields))
    except Exception as e:
        if ctx.obj["VERBOSE"]:
            console.log(e, e.response.json())
        raise GriffonException(
            f"Failed to fetch Affect with ID '{affect_uuid}'. "
            "Affect either does not exist or you have insufficient permissions. "
            "Consider running griffon with -v option for verbose error log."
        )

    data = data.to_dict()
    # remove status data from OSIDB server
    [data.pop(key) for key in ["dt", "env", "revision", "version"]]
    data.update((field, value) for field, value in params.items() if value is not None)

    if ctx.obj["EDITOR"]:
        data = click.edit(text=json.dumps(data, indent=4), editor=get_editor(), require_save=False)
        data = json.loads(data)

    try:
        data = session.affects.update(id=affect_uuid, form_data=data)
    except HTTPError as e:
        if ctx.obj["VERBOSE"]:
            console.log(e, e.response.json())
        raise GriffonException(
            f"Failed to update Affect with ID '{affect_uuid}'. "
            "You might have insufficient permission or you've supplied malformed data. "
            "Consider running griffon with -v option for verbose error log."
        )
    return cprint(data, ctx=ctx)


@affects.command(name="create")
@request_body_options(
    endpoint_module=osidb_api_v1_affects_create,
    exclude=["uuid", "created_dt", "updated_dt"],
)
@click.pass_context
@progress_bar()
def create_affect(ctx, **params):
    request_body_type = getattr(osidb_api_v1_affects_create, "REQUEST_BODY_TYPE", None)
    if request_body_type is None:
        raise GriffonException(
            "No request body template for Affect create. "
            "Is correct version of osidb-bindings installed?"
        )

    fields = filter_request_fields(
        request_body_type.get_fields(),
        exclude=["uuid", "created_dt", "updated_dt"],
    )
    params = multivalue_params_to_csv(params)

    session = OSIDBService.create_session()

    data = {field: "" for field in fields}
    data.update((field, value) for field, value in params.items() if value is not None)

    if ctx.obj["EDITOR"]:
        data = click.edit(
            text=json.dumps(data, indent=4, default=str), editor=get_editor(), require_save=False
        )
        data = json.loads(data)

    try:
        data = session.affects.create(form_data=data)
    except HTTPError as e:
        if ctx.obj["VERBOSE"]:
            console.log(e, e.response.json())
        raise GriffonException(
            "Failed to create Affect. "
            "You might have insufficient permission or you've supplied malformed data. "
            "Consider running griffon with -v option for verbose error log."
        )
    return cprint(data, ctx=ctx)


@affects.command(name="delete")
@click.option("--uuid", "affect_uuid", help="Affect UUID.", required=True)
@click.option(
    "--yes",
    is_flag=True,
    callback=abort_if_false,
    expose_value=False,
    prompt="Are you sure you delete affect?",
)
@click.pass_context
@progress_bar()
def delete_affect(ctx, affect_uuid, **params):
    session = OSIDBService.create_session()
    try:
        data = session.affects.delete(affect_uuid)
    except HTTPError as e:
        if ctx.obj["VERBOSE"]:
            console.log(e, e.response.json())
        raise GriffonException(
            f"Failed to delete {affect_uuid}. "
            "It either does not exist or you have insufficient permissions."
        )
    return cprint(data, ctx=ctx)
