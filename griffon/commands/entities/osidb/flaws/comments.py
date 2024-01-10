"""
osidb flaw comment entities operations
"""

import json
import logging

import click
from osidb_bindings.bindings.python_client.api.osidb import (
    osidb_api_v1_flaws_comments_create,
    osidb_api_v1_flaws_comments_list,
    osidb_api_v1_flaws_comments_retrieve,
)
from osidb_bindings.bindings.python_client.models import FlawComment
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

logger = logging.getLogger("griffon")


@click.group(help=f"{OSIDB_SERVER_URL}/osidb/api/v1/flaws/<id>/comments", name="comments")
@click.pass_context
def flaw_comments(ctx):
    """OSIDB Flaw Comments."""
    pass


@flaw_comments.command(name="get")
@click.option(
    "--flaw-id",
    "flaw_id",
    help="Flaw CVE-ID or UUID.",
    required=True,
)
@click.option("--uuid", "comment_uuid", help="Comment UUID.", required=True)
@query_params_options(
    entity="Flaw Comment",
    endpoint_module=osidb_api_v1_flaws_comments_retrieve,
    options_overrides={
        "include_fields": {"type": click.Choice(OSIDBService.get_fields(FlawComment))},
        "exclude_fields": {"type": click.Choice(OSIDBService.get_fields(FlawComment))},
        "include_meta_attr": {"type": click.Choice(OSIDBService.get_meta_attr_fields(FlawComment))},
    },
)
@click.pass_context
@progress_bar()
def get_flaw_comment(ctx, flaw_id, comment_uuid, **params):
    params = multivalue_params_to_csv(params)

    session = OSIDBService.create_session()
    data = session.flaws.comments.retrieve(flaw_id, comment_uuid, **params)
    return cprint(data, ctx=ctx)


@flaw_comments.command(name="list")
@click.option(
    "--flaw-id",
    "flaw_id",
    help="Flaw CVE-ID or UUID.",
    required=True,
)
@query_params_options(
    entity="Flaw Comments",
    endpoint_module=osidb_api_v1_flaws_comments_list,
    options_overrides={
        "include_fields": {"type": click.Choice(OSIDBService.get_fields(FlawComment))},
        "exclude_fields": {"type": click.Choice(OSIDBService.get_fields(FlawComment))},
        "include_meta_attr": {"type": click.Choice(OSIDBService.get_meta_attr_fields(FlawComment))},
    },
)
@click.pass_context
@progress_bar()
def list_flaw_comments(ctx, flaw_id, **params):
    # TODO: handle pagination
    # TODO: handle output
    session = OSIDBService.create_session()

    params = multivalue_params_to_csv(params)
    data = session.flaws.comments.retrieve_list(flaw_id, **params).results
    return cprint(data, ctx=ctx)


@flaw_comments.command(name="create")
@click.option(
    "--flaw-id",
    "flaw_id",
    help="Flaw CVE-ID or UUID.",
    required=True,
)
@request_body_options(
    endpoint_module=osidb_api_v1_flaws_comments_create,
    exclude=["uuid", "created_dt"],
)
@click.pass_context
@progress_bar()
def create_flaw_comment(ctx, flaw_id, **params):
    request_body_type = getattr(osidb_api_v1_flaws_comments_create, "REQUEST_BODY_TYPE", None)
    if request_body_type is None:
        raise GriffonException(
            "No request body template for Flaw Comment create. "
            "Is correct version of osidb-bindings installed?"
        )

    fields = filter_request_fields(
        request_body_type.get_fields(),
        exclude=["uuid", "created_dt"],
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
        data = session.flaws.comments.create(data, flaw_id=flaw_id)
    except HTTPError as e:
        if ctx.obj["VERBOSE"]:
            console.log(e, e.response.json())
        raise GriffonException(
            "Failed to create Flaw Comment. "
            "You might have insufficient permission or you've supplied malformed data. "
            "Consider running griffon with -v option for verbose error log."
        )
    return cprint(data, ctx=ctx)
