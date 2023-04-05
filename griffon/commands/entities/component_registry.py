"""
component-registry entity operations

"""
import concurrent.futures
import logging

import click

from griffon import CORGI_API_URL, CorgiService, progress_bar
from griffon.autocomplete import (
    get_component_names,
    get_component_purls,
    get_product_stream_names,
    get_product_stream_ofuris,
)
from griffon.output import console, cprint

logger = logging.getLogger("griffon")

default_conditions: dict = {}


@click.group(name="CORGI")
@click.pass_context
def component_registry_grp(ctx):
    pass


@component_registry_grp.group(help=f"{CORGI_API_URL}/api/v1/components")
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
@component_registry_grp.group(help=f"{CORGI_API_URL}/api/v1/product_streams")
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


@component_registry_grp.group(help=f"{CORGI_API_URL}/api/v1/builds")
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
