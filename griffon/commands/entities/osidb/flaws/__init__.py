"""
osidb flaw entities operations
"""

import json
import logging

import click
from osidb_bindings.bindings.python_client.api.osidb import (
    osidb_api_v1_flaws_create,
    osidb_api_v1_flaws_list,
    osidb_api_v1_flaws_retrieve,
    osidb_api_v1_flaws_update,
)
from osidb_bindings.bindings.python_client.models import Flaw
from requests import HTTPError

from griffon import OSIDB_SERVER_URL, OSIDBService, progress_bar
from griffon.commands.entities.helpers import (
    filter_request_fields,
    get_editor,
    multivalue_params_to_csv,
    query_params_options,
    request_body_options,
)
from griffon.exceptions import GriffonException
from griffon.output import console, cprint

from .acknowledgments import flaw_acknowledgments
from .comments import flaw_comments
from .cvss import flaw_cvss
from .package_versions import flaw_package_versions
from .references import flaw_references

logger = logging.getLogger("griffon")


@click.group(help=f"{OSIDB_SERVER_URL}/osidb/api/v1/flaws")
@click.pass_context
def flaws(ctx):
    """OSIDB Flaws."""


@flaws.command(name="list")
@query_params_options(
    entity="Flaw",
    endpoint_module=osidb_api_v1_flaws_list,
    options_overrides={
        "include_fields": {"type": click.Choice(OSIDBService.get_fields(Flaw))},
        "exclude_fields": {"type": click.Choice(OSIDBService.get_fields(Flaw))},
        "include_meta_attr": {"type": click.Choice(OSIDBService.get_meta_attr_fields(Flaw))},
    },
)
@click.pass_context
@progress_bar()
def list_flaws(ctx, **params):
    # TODO: handle output
    session = OSIDBService.create_session()

    params = multivalue_params_to_csv(params)
    return cprint(
        list(session.flaws.retrieve_list_iterator_async(max_results=5000, **params)), ctx=ctx
    )


@flaws.command(name="get")
@click.option(
    "--id",
    "flaw_id",
    help="Flaw CVE-ID or UUID.",
    required=True,
)
@query_params_options(
    entity="Flaw",
    endpoint_module=osidb_api_v1_flaws_retrieve,
    options_overrides={
        "include_fields": {"type": click.Choice(OSIDBService.get_fields(Flaw))},
        "exclude_fields": {"type": click.Choice(OSIDBService.get_fields(Flaw))},
        "include_meta_attr": {"type": click.Choice(OSIDBService.get_meta_attr_fields(Flaw))},
    },
)
@click.pass_context
@progress_bar()
def get_flaw(ctx, flaw_id, **params):
    params = multivalue_params_to_csv(params)

    session = OSIDBService.create_session()
    data = session.flaws.retrieve(flaw_id, **params)
    return cprint(data, ctx=ctx)


@flaws.command(name="update")
@click.option(
    "--id",
    "flaw_id",
    help="Flaw CVE-ID or UUID.",
    required=True,
)
@request_body_options(
    endpoint_module=osidb_api_v1_flaws_update, exclude=["uuid", "trackers", "created_dt"]
)
@click.pass_context
def update_flaw(ctx, flaw_id, **params):
    request_body_type = getattr(osidb_api_v1_flaws_update, "REQUEST_BODY_TYPE", None)
    if request_body_type is None:
        raise GriffonException(
            "No request body template for Flaw update. "
            "Is correct version of osidb-bindings installed?"
        )

    fields = filter_request_fields(
        request_body_type.get_fields(), exclude=["uuid", "trackers", "created_dt"]
    )
    params = multivalue_params_to_csv(params)

    session = OSIDBService.create_session()

    try:
        data = session.flaws.retrieve(id=flaw_id, include_fields=",".join(fields))
    except Exception as e:
        if ctx.obj["VERBOSE"]:
            console.log(e, e.response.json())
        raise GriffonException(
            f"Failed to fetch Flaw with ID '{flaw_id}'. "
            "Flaw either does not exist or you have insufficient permissions. "
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
        data = session.flaws.update(id=flaw_id, form_data=data)
    except HTTPError as e:
        if ctx.obj["VERBOSE"]:
            console.log(e, e.response.json())
        raise GriffonException(
            f"Failed to update Flaw with ID '{flaw_id}'. "
            "You might have insufficient permission or you've supplied malformed data. "
            "Consider running griffon with -v option for verbose error log."
        )
    return cprint(data, ctx=ctx)


@flaws.command(name="create")
@request_body_options(
    endpoint_module=osidb_api_v1_flaws_create,
    exclude=["uuid", "trackers", "created_dt", "updated_dt"],
)
@click.pass_context
@progress_bar()
def create_flaw(ctx, **params):
    request_body_type = getattr(osidb_api_v1_flaws_create, "REQUEST_BODY_TYPE", None)
    if request_body_type is None:
        raise GriffonException(
            "No request body template for Flaw create. "
            "Is correct version of osidb-bindings installed?"
        )

    fields = filter_request_fields(
        request_body_type.get_fields(),
        exclude=["uuid", "trackers", "created_dt", "updated_dt"],
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
        data = session.flaws.create(form_data=data)
    except HTTPError as e:
        if ctx.obj["VERBOSE"]:
            console.log(e, e.response.json())
        raise GriffonException(
            "Failed to create Flaw. "
            "You might have insufficient permission or you've supplied malformed data. "
            "Consider running griffon with -v option for verbose error log."
        )
    return cprint(data, ctx=ctx)


flaws.add_command(flaw_acknowledgments)
flaws.add_command(flaw_comments)
flaws.add_command(flaw_cvss)
flaws.add_command(flaw_package_versions)
flaws.add_command(flaw_references)
