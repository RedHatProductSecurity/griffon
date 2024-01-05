"""
osidb flaw package version entities operations
"""

import json
import logging

import click
from osidb_bindings.bindings.python_client.api.osidb import (
    osidb_api_v1_flaws_package_versions_create,
    osidb_api_v1_flaws_package_versions_list,
    osidb_api_v1_flaws_package_versions_retrieve,
    osidb_api_v1_flaws_package_versions_update,
)
from osidb_bindings.bindings.python_client.models import FlawPackageVersion
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


@click.group(
    help=f"{OSIDB_SERVER_URL}/osidb/api/v1/flaws/<id>/package_versions", name="package_versions"
)
@click.pass_context
def flaw_package_versions(ctx):
    """OSIDB Flaw Package Versions."""
    pass


@flaw_package_versions.command(name="get")
@click.option(
    "--flaw-id",
    "flaw_id",
    help="Flaw CVE-ID or UUID.",
    required=True,
)
@click.option("--uuid", "package_version_uuid", help="Package Version UUID.", required=True)
@query_params_options(
    entity="Flaw Package Version",
    endpoint_module=osidb_api_v1_flaws_package_versions_retrieve,
    options_overrides={
        "include_fields": {"type": click.Choice(OSIDBService.get_fields(FlawPackageVersion))},
        "exclude_fields": {"type": click.Choice(OSIDBService.get_fields(FlawPackageVersion))},
        "include_meta_attr": {
            "type": click.Choice(OSIDBService.get_meta_attr_fields(FlawPackageVersion))
        },
    },
)
@click.pass_context
@progress_bar()
def get_flaw_package_version(ctx, flaw_id, package_version_uuid, **params):
    params = multivalue_params_to_csv(params)

    session = OSIDBService.create_session()
    data = session.flaws.package_versions.retrieve(flaw_id, package_version_uuid, **params)
    return cprint(data, ctx=ctx)


@flaw_package_versions.command(name="list")
@click.option(
    "--flaw-id",
    "flaw_id",
    help="Flaw CVE-ID or UUID.",
    required=True,
)
@query_params_options(
    entity="Flaw Package Version",
    endpoint_module=osidb_api_v1_flaws_package_versions_list,
    options_overrides={
        "include_fields": {"type": click.Choice(OSIDBService.get_fields(FlawPackageVersion))},
        "exclude_fields": {"type": click.Choice(OSIDBService.get_fields(FlawPackageVersion))},
        "include_meta_attr": {
            "type": click.Choice(OSIDBService.get_meta_attr_fields(FlawPackageVersion))
        },
    },
)
@click.pass_context
@progress_bar()
def list_flaw_package_versions(ctx, flaw_id, **params):
    # TODO: handle pagination
    # TODO: handle output
    session = OSIDBService.create_session()

    params = multivalue_params_to_csv(params)
    data = session.flaws.package_versions.retrieve_list(flaw_id, **params).results
    return cprint(data, ctx=ctx)


@flaw_package_versions.command(name="create")
@click.option(
    "--flaw-id",
    "flaw_id",
    help="Flaw CVE-ID or UUID.",
    required=True,
)
@request_body_options(
    endpoint_module=osidb_api_v1_flaws_package_versions_create,
    exclude=["uuid", "created_dt"],
)
@click.pass_context
@progress_bar()
def create_flaw_package_version(ctx, flaw_id, **params):
    request_body_type = getattr(
        osidb_api_v1_flaws_package_versions_create, "REQUEST_BODY_TYPE", None
    )
    if request_body_type is None:
        raise GriffonException(
            "No request body template for Flaw Package Version create. "
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
        data = session.flaws.package_versions.create(data, flaw_id=flaw_id)
    except HTTPError as e:
        if ctx.obj["VERBOSE"]:
            console.log(e, e.response.json())
        raise GriffonException(
            "Failed to create Flaw Package Version. "
            "You might have insufficient permission or you've supplied malformed data. "
            "Consider running griffon with -v option for verbose error log."
        )
    return cprint(data, ctx=ctx)


@flaw_package_versions.command(name="update")
@click.option(
    "--flaw-id",
    "flaw_id",
    help="Flaw CVE-ID or UUID.",
    required=True,
)
@click.option("--uuid", "package_version_uuid", help="Package Version UUID.", required=True)
@request_body_options(endpoint_module=osidb_api_v1_flaws_package_versions_update, exclude=["uuid"])
@click.pass_context
@progress_bar()
def update_flaw_package_version(ctx, flaw_id, package_version_uuid, **params):
    request_body_type = getattr(
        osidb_api_v1_flaws_package_versions_update, "REQUEST_BODY_TYPE", None
    )
    if request_body_type is None:
        raise GriffonException(
            "No request body template for Flaw Package Version update. "
            "Is correct version of osidb-bindings installed?"
        )

    fields = filter_request_fields(request_body_type.get_fields(), exclude=["uuid"])
    params = multivalue_params_to_csv(params)

    session = OSIDBService.create_session()

    try:
        data = session.flaws.package_versions.retrieve(
            flaw_id, package_version_uuid, include_fields=",".join(fields)
        )
    except Exception as e:
        if ctx.obj["VERBOSE"]:
            console.log(e, e.response.json())
        raise GriffonException(
            f"Failed to fetch Flaw Package Version with ID '{package_version_uuid}'. "
            "Flaw or Flaw Package Version either does not exist or you have "
            "insufficient permissions. "
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
        data = session.flaws.package_versions.update(flaw_id, data, package_version_uuid)
    except HTTPError as e:
        if ctx.obj["VERBOSE"]:
            console.log(e, e.response.json())
        raise GriffonException(
            f"Failed to update Flaw Package Version with ID '{package_version_uuid}'. "
            "You might have insufficient permission or you've supplied malformed data. "
            "Consider running griffon with -v option for verbose error log."
        )
    return cprint(data, ctx=ctx)


@flaw_package_versions.command(name="delete")
@click.option(
    "--flaw-id",
    "flaw_id",
    help="Flaw CVE-ID or UUID.",
    required=True,
)
@click.option("--uuid", "package_version_uuid", help="Package Version UUID.", required=True)
@click.option(
    "--yes",
    is_flag=True,
    callback=abort_if_false,
    expose_value=False,
    prompt="Are you sure you want to delete Flaw Package Version?",
)
@click.pass_context
@progress_bar()
def delete_flaw_package_version(ctx, flaw_id, package_versions_uuid, **params):
    session = OSIDBService.create_session()
    try:
        data = session.flaws.package_versions.delete(flaw_id, package_versions_uuid)
    except HTTPError as e:
        if ctx.obj["VERBOSE"]:
            console.log(e, e.response.json())
        raise GriffonException(
            f"Failed to delete Flaw Package Version {package_versions_uuid}. "
            "It either does not exist or you have insufficient permissions."
        )
    return cprint(data, ctx=ctx)
