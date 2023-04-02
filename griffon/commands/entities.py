"""
entity operations

"""
import concurrent.futures
import inspect
import json
import logging
from datetime import datetime
from enum import Enum
from itertools import chain
from types import ModuleType
from typing import Callable, Optional, Union, get_args, get_origin

import click
from osidb_bindings.bindings.python_client.api.osidb import (
    osidb_api_v1_affects_create,
    osidb_api_v1_affects_list,
    osidb_api_v1_affects_retrieve,
    osidb_api_v1_affects_update,
    osidb_api_v1_flaws_create,
    osidb_api_v1_flaws_list,
    osidb_api_v1_flaws_retrieve,
    osidb_api_v1_flaws_update,
    osidb_api_v1_trackers_list,
    osidb_api_v1_trackers_retrieve,
)
from osidb_bindings.bindings.python_client.models import Affect, Flaw, Tracker
from osidb_bindings.bindings.python_client.types import OSIDBModel
from requests import HTTPError

from griffon import (
    CORGI_API_URL,
    OSIDB_API_URL,
    CorgiService,
    OSIDBService,
    get_config_option,
    progress_bar,
)
from griffon.autocomplete import (
    get_component_names,
    get_component_purls,
    get_product_stream_names,
    get_product_stream_ofuris,
)
from griffon.output import console, cprint

logger = logging.getLogger("griffon")

default_conditions: dict = {}


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


@click.group(name="entities", help="Entity operations (UNDER DEVELOPMENT).")
@click.option("--open-browser", is_flag=True, help="open browser to service results.")
@click.option("--limit", default=10, help="# of items returned by list operations.")
@click.pass_context
def entities_grp(ctx, open_browser, limit):
    ctx.ensure_object(dict)
    ctx.obj["open_browser"] = open_browser
    ctx.obj["limit"] = limit


# flaws
@entities_grp.group(help=f"{OSIDB_API_URL}/osidb/api/v1/flaws")
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
@progress_bar
def list_flaws(ctx, **params):
    # TODO: handle pagination
    # TODO: handle output
    session = OSIDBService.create_session()

    params = multivalue_params_to_csv(params)
    data = session.flaws.retrieve_list(**params).results
    return cprint(data, ctx=ctx)


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
@progress_bar
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
@progress_bar
def update_flaw(ctx, flaw_id, **params):
    request_body_type = getattr(osidb_api_v1_flaws_update, "REQUEST_BODY_TYPE", None)
    if request_body_type is None:
        raise click.ClickException(
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
        raise click.ClickException(
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
        raise click.ClickException(
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
@progress_bar
def create_flaw(ctx, **params):
    request_body_type = getattr(osidb_api_v1_flaws_create, "REQUEST_BODY_TYPE", None)
    if request_body_type is None:
        raise click.ClickException(
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
        raise click.ClickException(
            "Failed to create Flaw. "
            "You might have insufficient permission or you've supplied malformed data. "
            "Consider running griffon with -v option for verbose error log."
        )
    return cprint(data, ctx=ctx)


# affects
@entities_grp.group(help=f"{OSIDB_API_URL}/osidb/api/v1/affects")
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
@progress_bar
def list_affects(ctx, **params):
    # TODO: handle pagination
    # TODO: handle output
    session = OSIDBService.create_session()

    params = multivalue_params_to_csv(params)
    data = session.affects.retrieve_list(**params).results
    return cprint(data, ctx=ctx)


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
@progress_bar
def get_affect(ctx, affect_uuid, **params):
    """
    For parameter reference see:
    <OSIDB_API_URL>/osidb/api/v1/schema/swagger-ui - /osidb/api/v1/affects/{uuid}
    """
    params = multivalue_params_to_csv(params)

    session = OSIDBService.create_session()
    data = session.affects.retrieve(affect_uuid, **params)
    return cprint(data, ctx=ctx)


@affects.command(name="update")
@click.option("--uuid", "affect_uuid", help="Affect UUID.", required=True)
@request_body_options(endpoint_module=osidb_api_v1_affects_update, exclude=["uuid"])
@click.pass_context
@progress_bar
def update_affect(ctx, affect_uuid, **params):
    request_body_type = getattr(osidb_api_v1_affects_update, "REQUEST_BODY_TYPE", None)
    if request_body_type is None:
        raise click.ClickException(
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
        raise click.ClickException(
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
        raise click.ClickException(
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
@progress_bar
def create_affect(ctx, **params):
    request_body_type = getattr(osidb_api_v1_affects_create, "REQUEST_BODY_TYPE", None)
    if request_body_type is None:
        raise click.ClickException(
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
        raise click.ClickException(
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
@progress_bar
def delete_affect(ctx, affect_uuid, **params):
    session = OSIDBService.create_session()
    try:
        data = session.affects.delete(affect_uuid)
    except HTTPError as e:
        if ctx.obj["VERBOSE"]:
            console.log(e, e.response.json())
        raise click.ClickException(
            f"Failed to delete {affect_uuid}. "
            "It either does not exist or you have insufficient permissions."
        )
    return cprint(data, ctx=ctx)


# trackers
@entities_grp.group(help=f"{OSIDB_API_URL}/osidb/api/v1/trackers")
@click.pass_context
def trackers(ctx):
    """OSIDB Trackers."""
    pass


@trackers.command(name="list")
@query_params_options(
    entity="Tracker",
    endpoint_module=osidb_api_v1_trackers_list,
    options_overrides={
        "include_fields": {"type": click.Choice(OSIDBService.get_fields(Tracker))},
        "exclude_fields": {"type": click.Choice(OSIDBService.get_fields(Tracker))},
        "include_meta_attr": {"type": click.Choice(OSIDBService.get_meta_attr_fields(Tracker))},
    },
)
@click.pass_context
def list_trackers(ctx, **params):
    # TODO: handle pagination
    # TODO: handle output
    session = OSIDBService.create_session()

    params = multivalue_params_to_csv(params)
    data = session.trackers.retrieve_list(**params).results
    return cprint(data, ctx=ctx)


@trackers.command(name="get")
@click.option("--uuid", "tracker_uuid", help="Tracker UUID.", required=True)
@query_params_options(
    entity="Tracker",
    endpoint_module=osidb_api_v1_trackers_retrieve,
    options_overrides={
        "include_fields": {"type": click.Choice(OSIDBService.get_fields(Tracker))},
        "exclude_fields": {"type": click.Choice(OSIDBService.get_fields(Tracker))},
        "include_meta_attr": {"type": click.Choice(OSIDBService.get_meta_attr_fields(Tracker))},
    },
)
@click.pass_context
@progress_bar
def get_tracker(ctx, tracker_uuid, **params):
    params = multivalue_params_to_csv(params)

    session = OSIDBService.create_session()
    data = session.trackers.retrieve(tracker_uuid, **params)
    return cprint(data, ctx=ctx)


# components
@entities_grp.group(help=f"{CORGI_API_URL}/api/v1/components")
@click.pass_context
def components(ctx):
    pass


@components.command(name="list")
@click.argument("component_name", required=False)
@click.option("--namespace", type=click.Choice(CorgiService.get_component_namespaces()), help="")
@click.option("--ofuri", shell_complete=get_product_stream_ofuris)
@click.option("--re_purl", shell_complete=get_component_purls)
@click.option("--re_name", shell_complete=get_component_names)
@click.option("--version")
@click.option(
    "--type",
    "component_type",
    type=click.Choice(CorgiService.get_component_types()),
    help="",  # noqa
)
@click.option(
    "--arch",
    type=click.Choice(CorgiService.get_component_arches()),
)
@click.option("--product-stream-name", shell_complete=get_product_stream_names)
@click.option("--product-stream-ofuri", shell_complete=get_product_stream_ofuris)
@click.pass_context
@progress_bar
def list_components(
    ctx,
    component_name,
    namespace,
    ofuri,
    re_purl,
    re_name,
    version,
    component_type,
    arch,
    product_stream_name,
    product_stream_ofuri,
):
    """Retrieve a list of Components."""

    if (
        not component_name
        and not ofuri
        and not re_purl
        and not re_name
        and not version
        and not arch
        and not namespace
        and not component_type
        and not product_stream_name
        and not product_stream_ofuri
    ):
        click.echo(ctx.get_help())
        exit(0)
    session = CorgiService.create_session()

    conditions = default_conditions
    conditions[
        "include_fields"
    ] = "link,purl,nvr,version,type,name,upstreams,related_url,download_url"

    # TODO- condition union could be a separate helper function

    if component_name:
        conditions["name"] = component_name

    if namespace:
        conditions["namespace"] = namespace
    if ofuri:
        conditions["ofuri"] = ofuri
    if re_purl:
        conditions["re_purl"] = re_purl
    if re_name:
        conditions["re_name"] = re_name
    if version:
        conditions["version"] = version
    if arch:
        conditions["arch"] = arch
    if component_type:
        conditions["type"] = component_type
    if product_stream_ofuri:
        conditions["product_streams"] = product_stream_ofuri

    # TODO- This kind of optimisation should probably be developed in the
    #       service binding itself rather then here
    logger.debug("starting parallel http requests")
    component_cnt = session.components.retrieve_list(**conditions).count
    if component_cnt < 3000000:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            components = list()
            for batch in range(0, component_cnt, 1200):
                futures.append(
                    executor.submit(
                        session.components.retrieve_list,
                        **conditions,
                        offset=batch,
                        limit=1200,  # noqa
                    )
                )

            for future in concurrent.futures.as_completed(futures):
                try:
                    components.extend(future.result().results)
                except Exception as exc:
                    logger.warning("%r generated an exception: %s" % (future, exc))

            data = sorted(components, key=lambda d: d.purl)
            return cprint(data, ctx=ctx)
    else:
        console.print("downloading too many")


@components.command(name="get")
@click.option("--uuid", "component_uuid")
@click.option("--purl", shell_complete=get_component_purls, help="Purl are URI and must be quoted.")
@click.option("--nvr")
@click.pass_context
@progress_bar
def get_component(ctx, component_uuid, purl, nvr):
    """Retrieve Component."""
    if not component_uuid and not purl and not nvr:
        click.echo(ctx.get_help())
        exit(0)
    session = CorgiService.create_session()
    data = session.components.retrieve_list(purl=purl)
    return cprint(data, ctx=ctx)


@components.command(
    name="summary",
    help="Get Component summaries.",
)
@click.argument(
    "component_name",
    required=False,
)
@click.option(
    "-s",
    "strict_name_search",
    is_flag=True,
    default=False,
    help="Strict search, exact match of name.",
)
@click.pass_context
@progress_bar
def get_component_summary(ctx, component_name, strict_name_search):
    """Get Component summary."""
    if not component_name:
        click.echo(ctx.get_help())
        exit(0)
    session = CorgiService.create_session()

    cond = {
        "include_fields": "name,type,download_url,purl,tags,arch,release,version,product_streams,upstreams,related_url",  # noqa
        "name": component_name,
    }
    components = session.components.retrieve_list(**cond, limit=10000)
    product_streams = []
    upstreams = []
    versions = []
    releases = []
    arches = []
    related_urls = []
    download_urls = []
    tags = []
    component_type = None
    for component in components.results:
        component_type = component.type
        related_urls.append(component.related_url)
        arches.append(component.arch)
        versions.append(component.version)
        releases.append(component.release)
        tags.extend(component.tags)
        for upstream in component.upstreams:
            upstreams.append(upstream["purl"])
        for ps in component.product_streams:
            product_streams.append(ps["name"])

    cond = {
        "include_fields": "name,purl,version,type,tags,arch,release,product_streams",  # noqa
        "name": component_name,
        "view": "latest",
    }
    latest_components = session.components.retrieve_list(**cond, limit=10000)

    latest = []

    for latest_component in latest_components.results:
        latest.append(
            {
                "product_stream": latest_component["product_stream"],
                "purl": latest_component.purl,
            }
        )
    data = {
        "link": f"{CORGI_API_URL}/api/v1/components?name={component_name}",
        "type": component_type,
        "name": component_name,
        "tags": sorted(list(set(tags))),
        "count": len(components.results),
        "product_streams": sorted(list(set(product_streams))),
        "related_urls": sorted(list(set(related_urls))),
        "download_urls": sorted(list(set(download_urls))),
        "releases": sorted(list(set(releases))),
        "upstreams": sorted(list(set(upstreams))),
        "arches": sorted(list(set(arches))),
        "versions": sorted(list(set(versions))),
        "latest": latest,
    }
    cprint(data, ctx=ctx)


@components.command(name="provides")
@click.option("--uuid", "component_uuid")
@click.option("--purl", shell_complete=get_component_purls, help="Purl are URI and must be quoted.")
@click.pass_context
@progress_bar
def get_component_provides(ctx, component_uuid, purl):
    """Retrieve all Components provided by a Component."""
    if not component_uuid and not purl:
        click.echo(ctx.get_help())
        exit(0)
    session = CorgiService.create_session()
    if component_uuid:
        data = session.components.retrieve(component_uuid).provides
        return cprint(data, ctx=ctx)
    else:
        c = session.components.retrieve_list(purl=purl)
        if c:
            data = session.components.retrieve(c["uuid"]).provides
            return cprint(data, ctx=ctx)


@components.command(name="sources")
@click.option("--uuid", "component_uuid")
@click.option("--purl", shell_complete=get_component_purls, help="Purl are URI and must be quoted.")
@click.pass_context
@progress_bar
def get_component_sources(ctx, component_uuid, purl):
    """Retrieve all Components that contain Component."""
    if not component_uuid and not purl:
        click.echo(ctx.get_help())
        exit(0)
    session = CorgiService.create_session()
    if component_uuid:
        data = session.components.retrieve(component_uuid).sources
        return cprint(data, ctx=ctx)
    else:
        c = session.components.retrieve_list(purl=purl)
        if c:
            data = session.components.retrieve(c["uuid"]).sources
            return cprint(data, ctx=ctx)


@components.command(name="manifest")
@click.option("--uuid", "component_uuid")
@click.option("--purl", shell_complete=get_component_purls, help="Purl are URI and must be quoted.")
@click.pass_context
@progress_bar
def get_component_manifest(ctx, component_uuid, purl):
    """Retrieve Component manifest."""
    if not component_uuid and not purl:
        click.echo(ctx.get_help())
        exit(0)
    session = CorgiService.create_session()
    if component_uuid:
        data = session.components.retrieve_manifest(component_uuid)
        return cprint(data, ctx=ctx)
    else:
        c = session.components.retrieve_list(purl=purl)
        if c:
            data = session.components.retrieve_manifest(c["uuid"])
            return cprint(data, ctx=ctx)


# product streams
@entities_grp.group(help=f"{CORGI_API_URL}/api/v1/product_streams")
@click.pass_context
def product_streams(ctx):
    pass


@product_streams.command(name="list")
@click.argument(
    "product_stream_name",
    required=False,
    type=click.STRING,
    shell_complete=get_product_stream_names,
)
@click.pass_context
def list_product_streams(ctx, product_stream_name):
    """Retrieve a list of Product Streams."""
    session = CorgiService.create_session()
    cond = default_conditions
    if product_stream_name:
        cond["re_name"] = product_stream_name
    data = session.product_streams.retrieve_list(**cond, limit=1000).results
    return cprint(data, ctx=ctx)


@product_streams.command(name="get")
@click.argument(
    "product_stream_name",
    required=False,
    type=click.STRING,
    shell_complete=get_product_stream_names,
)
@click.option("--inactive", is_flag=True, default=False, help="Show inactive project streams")
@click.option("--ofuri", "ofuri", type=click.STRING, shell_complete=get_product_stream_ofuris)
@click.pass_context
@progress_bar
def get_product_stream(ctx, product_stream_name, inactive, ofuri):
    """Retrieve Product Stream."""
    if not ofuri and not product_stream_name:
        click.echo(ctx.get_help())
        exit(0)
    session = CorgiService.create_session()
    cond = {}
    if ofuri:
        cond["ofuri"] = ofuri
    if product_stream_name:
        cond["name"] = product_stream_name
    data = session.product_streams.retrieve_list(**cond)
    return cprint(data, ctx=ctx)


@product_streams.command(name="latest-components")
@click.argument(
    "product_stream_name",
    required=False,
    type=click.STRING,
    shell_complete=get_product_stream_names,
)
@click.option("--namespace", type=click.Choice(CorgiService.get_component_namespaces()), help="")
@click.option("--ofuri", "ofuri", type=click.STRING, shell_complete=get_product_stream_ofuris)
@click.option("--view", default="summary")
@click.pass_context
def get_product_stream_components(ctx, product_stream_name, namespace, ofuri, view):
    """Retrieve Product Stream latest Components."""
    if not ofuri and not product_stream_name:
        click.echo(ctx.get_help())
        exit(0)
    ctx.invoke(list_components, ofuri=ofuri)


@product_streams.command(name="manifest")
@click.argument(
    "product_stream_name",
    required=False,
    type=click.STRING,
    shell_complete=get_product_stream_names,
)
@click.option("--ofuri", "ofuri", type=click.STRING, shell_complete=get_product_stream_ofuris)
@click.pass_context
def get_product_stream_manifest(ctx, product_stream_name, ofuri):
    """Retrieve Product Stream manifest."""
    if not ofuri and not product_stream_name:
        click.echo(ctx.get_help())
        exit(0)
    session = CorgiService.create_session()
    pv = None
    if ofuri:
        pv = session.product_streams.retrieve_list(ofuri=ofuri).additional_properties
    if product_stream_name:
        pv = session.product_streams.retrieve_list(name=product_stream_name).additional_properties
    if pv:
        data = session.product_streams.retrieve_manifest(pv["uuid"])
        return cprint(data, ctx=ctx)


@entities_grp.group(help=f"{CORGI_API_URL}/api/v1/builds")
@click.pass_context
def builds(ctx):
    pass


@builds.command(name="list")
@click.argument("software_build_name", required=False)
@click.pass_context
def list_software_builds(ctx, software_build_name):
    """Retrieve a list of Software Builds."""
    session = CorgiService.create_session()
    cond = default_conditions
    if software_build_name:
        cond["name"] = software_build_name
    data = session.builds.retrieve_list(**cond, limit=1000).results
    return cprint(data, ctx=ctx)


@builds.command(name="get")
@click.argument("build_id", required=False)
@click.pass_context
def get_software_builds(ctx, build_id):
    """Retrieve Software Build."""
    session = CorgiService.create_session()
    data = session.builds.retrieve(build_id)
    return cprint(data, ctx=ctx)
