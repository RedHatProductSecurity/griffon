"""
osidb affect CVSS entities operations
"""

import json
import logging

import click
from osidb_bindings.bindings.python_client.api.osidb import (
    osidb_api_v1_affects_cvss_scores_create,
    osidb_api_v1_affects_cvss_scores_list,
    osidb_api_v1_affects_cvss_scores_retrieve,
    osidb_api_v1_affects_cvss_scores_update,
)
from osidb_bindings.bindings.python_client.models import AffectCVSS
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


@click.group(help=f"{OSIDB_SERVER_URL}/osidb/api/v1/affects/<id>/cvss_scores", name="cvss")
@click.pass_context
def affect_cvss(ctx):
    """OSIDB Affect CVSS."""
    pass


@affect_cvss.command(name="get")
@click.option(
    "--affect-id",
    "affect_id",
    help="affect CVE-ID or UUID.",
    required=True,
)
@click.option("--uuid", "cvss_uuid", help="CVSS UUID.", required=True)
@query_params_options(
    entity="affect CVSS",
    endpoint_module=osidb_api_v1_affects_cvss_scores_retrieve,
    options_overrides={
        "include_fields": {"type": click.Choice(OSIDBService.get_fields(AffectCVSS))},
        "exclude_fields": {"type": click.Choice(OSIDBService.get_fields(AffectCVSS))},
        "include_meta_attr": {"type": click.Choice(OSIDBService.get_meta_attr_fields(AffectCVSS))},
    },
)
@click.pass_context
@progress_bar()
def get_affect_cvss(ctx, affect_id, cvss_uuid, **params):
    params = multivalue_params_to_csv(params)

    session = OSIDBService.create_session()
    data = session.affects.cvss_scores.retrieve(affect_id, cvss_uuid, **params)
    return cprint(data, ctx=ctx)


@affect_cvss.command(name="list")
@click.option(
    "--affect-id",
    "affect_id",
    help="affect CVE-ID or UUID.",
    required=True,
)
@query_params_options(
    entity="affect CVSS",
    endpoint_module=osidb_api_v1_affects_cvss_scores_list,
    options_overrides={
        "include_fields": {"type": click.Choice(OSIDBService.get_fields(AffectCVSS))},
        "exclude_fields": {"type": click.Choice(OSIDBService.get_fields(AffectCVSS))},
        "include_meta_attr": {"type": click.Choice(OSIDBService.get_meta_attr_fields(AffectCVSS))},
    },
)
@click.pass_context
@progress_bar()
def list_affect_cvss(ctx, affect_id, **params):
    # TODO: handle pagination
    # TODO: handle output
    session = OSIDBService.create_session()

    params = multivalue_params_to_csv(params)
    data = session.affects.cvss_scores.retrieve_list(affect_id, **params).results
    return cprint(data, ctx=ctx)


@affect_cvss.command(name="create")
@click.option(
    "--affect-id",
    "affect_id",
    help="affect CVE-ID or UUID.",
    required=True,
)
@request_body_options(
    endpoint_module=osidb_api_v1_affects_cvss_scores_create,
    exclude=["uuid", "created_dt"],
)
@click.pass_context
@progress_bar()
def create_affect_cvss(ctx, affect_id, **params):
    request_body_type = getattr(osidb_api_v1_affects_cvss_scores_create, "REQUEST_BODY_TYPE", None)
    if request_body_type is None:
        raise GriffonException(
            "No request body template for affect CVSS create. "
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
        data = session.affects.cvss_scores.create(data, affect_id=affect_id)
    except HTTPError as e:
        if ctx.obj["VERBOSE"]:
            console.log(e, e.response.json())
        raise GriffonException(
            "Failed to create affect CVSS. "
            "You might have insufficient permission or you've supplied malformed data. "
            "Consider running griffon with -v option for verbose error log."
        )
    return cprint(data, ctx=ctx)


@affect_cvss.command(name="update")
@click.option(
    "--affect-id",
    "affect_id",
    help="affect CVE-ID or UUID.",
    required=True,
)
@click.option("--uuid", "cvss_uuid", help="CVSS UUID.", required=True)
@request_body_options(endpoint_module=osidb_api_v1_affects_cvss_scores_update, exclude=["uuid"])
@click.pass_context
@progress_bar()
def update_affect_cvss(ctx, affect_id, cvss_uuid, **params):
    request_body_type = getattr(osidb_api_v1_affects_cvss_scores_update, "REQUEST_BODY_TYPE", None)
    if request_body_type is None:
        raise GriffonException(
            "No request body template for affect CVSS update. "
            "Is correct version of osidb-bindings installed?"
        )

    fields = filter_request_fields(request_body_type.get_fields(), exclude=["uuid"])
    params = multivalue_params_to_csv(params)

    session = OSIDBService.create_session()

    try:
        data = session.affects.cvss_scores.retrieve(
            affect_id, cvss_uuid, include_fields=",".join(fields)
        )
    except Exception as e:
        if ctx.obj["VERBOSE"]:
            console.log(e, e.response.json())
        raise GriffonException(
            f"Failed to fetch affect CVSS with ID '{cvss_uuid}'. "
            "affect or affect CVSS either does not exist or you have insufficient permissions. "
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
        data = session.affects.cvss_scores.update(affect_id, data, cvss_uuid)
    except HTTPError as e:
        if ctx.obj["VERBOSE"]:
            console.log(e, e.response.json())
        raise GriffonException(
            f"Failed to update affect CVSS with ID '{cvss_uuid}'. "
            "You might have insufficient permission or you've supplied malformed data. "
            "Consider running griffon with -v option for verbose error log."
        )
    return cprint(data, ctx=ctx)


@affect_cvss.command(name="delete")
@click.option(
    "--affect-id",
    "affect_id",
    help="affect CVE-ID or UUID.",
    required=True,
)
@click.option("--uuid", "cvss_uuid", help="CVSS UUID.", required=True)
@click.option(
    "--yes",
    is_flag=True,
    callback=abort_if_false,
    expose_value=False,
    prompt="Are you sure you want to delete affect CVSS?",
)
@click.pass_context
@progress_bar()
def delete_affect_cvss(ctx, affect_id, cvss_uuid, **params):
    session = OSIDBService.create_session()
    try:
        data = session.affects.cvss_scores.delete(affect_id, cvss_uuid)
    except HTTPError as e:
        if ctx.obj["VERBOSE"]:
            console.log(e, e.response.json())
        raise GriffonException(
            f"Failed to delete affect CVSS {cvss_uuid}. "
            "It either does not exist or you have insufficient permissions."
        )
    return cprint(data, ctx=ctx)
