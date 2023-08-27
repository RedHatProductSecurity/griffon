"""
corgi entity operations

"""
import logging

import click
import requests
from component_registry_bindings.bindings.python_client.api.v1 import (
    v1_builds_list,
    v1_builds_retrieve,
    v1_channels_list,
    v1_channels_retrieve,
    v1_components_list,
    v1_components_retrieve,
    v1_product_streams_list,
    v1_product_streams_retrieve,
    v1_product_variants_list,
    v1_product_variants_retrieve,
    v1_product_versions_list,
    v1_product_versions_retrieve,
    v1_products_list,
    v1_products_retrieve,
)
from component_registry_bindings.bindings.python_client.models import (
    Channel,
    Component,
    Product,
    ProductStream,
    ProductVariant,
    ProductVersion,
    SoftwareBuild,
)

from griffon import (
    COMMUNITY_COMPONENTS_API_URL,
    CORGI_API_URL,
    CommunityComponentService,
    progress_bar,
)
from griffon.autocomplete import (
    get_component_purls,
    get_product_stream_names,
    get_product_stream_ofuris,
    get_product_version_ofuris,
)
from griffon.commands.entities.helpers import (
    multivalue_params_to_csv,
    query_params_options,
)
from griffon.output import console, cprint

logger = logging.getLogger("griffon")

default_conditions: dict = {}


@click.group(name="community-component-registry")
@click.pass_context
def commmunity_components_grp(ctx):
    pass


# COMPONENTS


@commmunity_components_grp.group(help=f"{COMMUNITY_COMPONENTS_API_URL}/api/v1/components")
@click.pass_context
def components(ctx):
    """Corgi Components."""


@components.command(name="list")
@click.argument("component_name", required=False)
@click.option(
    "-s",
    "strict_name_search",
    is_flag=True,
    default=False,
    help="Strict search, exact match of component name.",
)
@query_params_options(
    entity="Component",
    endpoint_module=v1_components_list,
    options_overrides={
        "include_fields": {"type": click.Choice(CommunityComponentService.get_fields(Component))},
    },
)
@click.pass_context
@progress_bar
def list_components(ctx, strict_name_search, component_name, **params):
    is_params_empty = [False for v in params.values() if v]
    if not component_name and not is_params_empty:
        click.echo(ctx.get_help())
        exit(0)
    if strict_name_search:
        params["name"] = component_name
    elif component_name:
        params["re_name"] = component_name

    if not params["include_fields"]:
        params[
            "include_fields"
        ] = "link,uuid,purl,nvr,version,type,name,upstreams,related_url,download_url"

    session = CommunityComponentService.create_session()
    return cprint(
        list(session.components.retrieve_list_iterator_async(max_results=5000, **params)), ctx=ctx
    )


@components.command(name="get")
@click.argument("component_id", required=False)
@click.option("--purl", shell_complete=get_component_purls, help="purls must be quoted!")
@query_params_options(
    entity="Component",
    endpoint_module=v1_components_retrieve,
    options_overrides={
        "include_fields": {"type": click.Choice(CommunityComponentService.get_fields(Component))},
    },
)
@click.pass_context
@progress_bar
def get_component(ctx, component_id, purl, **params):
    is_params_empty = [False for v in params.values() if v]
    if not component_id and not purl and not is_params_empty:
        click.echo(ctx.get_help())
        exit(0)

    if purl:
        params["purl"] = purl

    if not params["include_fields"]:
        params[
            "include_fields"
        ] = "link,purl,nvr,version,type,name,upstreams,related_url,download_url"

    params = multivalue_params_to_csv(params)

    session = CommunityComponentService.create_session()
    if component_id:
        data = session.components.retrieve(component_id, **params)
    else:
        data = session.components.retrieve_list(**params)
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
@query_params_options(
    entity="Component",
    endpoint_module=v1_components_list,
    options_overrides={
        "include_fields": {"type": click.Choice(CommunityComponentService.get_fields(Component))},
    },
)
@click.pass_context
@progress_bar
def get_component_summary(ctx, component_name, strict_name_search, **params):
    """Get Component summary."""
    is_params_empty = [False for v in params.values() if v]
    if not component_name and not is_params_empty:
        click.echo(ctx.get_help())
        exit(0)
    session = CommunityComponentService.create_session()

    cond = {
        "include_fields": "name,type,download_url,purl,tags,arch,release,version,product_streams,upstreams,related_url",  # noqa
        "name": component_name,
    }
    components = session.components.retrieve_list_iterator_async(max_results=5000, **cond)
    product_streams = []
    upstreams = []
    versions = []
    releases = []
    arches = []
    related_urls = []
    download_urls = []
    tags = []
    component_type = None
    for component in components:
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
    }
    cprint(data, ctx=ctx)


@components.command(name="provides")
@click.option("--uuid", "component_uuid")
@click.option("--purl", shell_complete=get_component_purls, help="Purl are URI and must be quoted.")
@query_params_options(
    entity="Component",
    endpoint_module=v1_components_list,
    options_overrides={
        "include_fields": {"type": click.Choice(CommunityComponentService.get_fields(Component))},
    },
)
@click.pass_context
@progress_bar
def get_component_provides(ctx, component_uuid, purl, **params):
    """Retrieve all Components provided by a Component."""
    is_params_empty = [False for v in params.values() if v]
    if not component_uuid and not purl and not is_params_empty:
        click.echo(ctx.get_help())
        exit(0)
    if not params["include_fields"]:
        params[
            "include_fields"
        ] = "link,purl,nvr,version,type,name,upstreams,related_url,download_url"
    if purl:
        params["sources"] = purl

    session = CommunityComponentService.create_session()
    if component_uuid:
        purl = session.components.retrieve(component_uuid).purl
        params["sources"] = purl
        return cprint(
            list(session.components.retrieve_list_iterator_async(max_results=5000, **params)),
            ctx=ctx,
        )
    else:
        return cprint(
            list(session.components.retrieve_list_iterator_async(max_results=5000, **params)),
            ctx=ctx,
        )


@components.command(name="sources")
@click.option("--uuid", "component_uuid")
@click.option("--purl", shell_complete=get_component_purls, help="Purl are URI and must be quoted.")
@query_params_options(
    entity="Component",
    endpoint_module=v1_components_list,
    options_overrides={
        "include_fields": {"type": click.Choice(CommunityComponentService.get_fields(Component))},
    },
)
@click.pass_context
@progress_bar
def get_component_sources(ctx, component_uuid, purl, **params):
    """Retrieve all Components that contain Component."""
    is_params_empty = [False for v in params.values() if v]
    if not component_uuid and not purl and not is_params_empty:
        click.echo(ctx.get_help())
        exit(0)
    if not params["include_fields"]:
        params[
            "include_fields"
        ] = "link,purl,nvr,version,type,name,upstreams,related_url,download_url"
    if purl:
        params["provides"] = purl
    session = CommunityComponentService.create_session()
    if component_uuid:
        purl = session.components.retrieve(component_uuid).purl
        params["provides"] = purl
        return cprint(
            list(session.components.retrieve_list_iterator_async(max_results=5000, **params)),
            ctx=ctx,
        )
    else:
        return cprint(
            list(session.components.retrieve_list_iterator_async(max_results=5000, **params)),
            ctx=ctx,
        )


@components.command(name="manifest")
@click.option("--uuid", "component_uuid")
@click.option("--purl", shell_complete=get_component_purls, help="Purl are URI and must be quoted.")
@click.option(
    "--spdx-json",
    "spdx_json_format",
    is_flag=True,
    default=False,
    help="Generate spdx manifest (json).",
)
@click.pass_context
@progress_bar
def get_component_manifest(ctx, component_uuid, purl, spdx_json_format):
    """Retrieve Component manifest."""
    if not component_uuid and not purl:
        click.echo(ctx.get_help())
        exit(0)
    if spdx_json_format:
        ctx.ensure_object(dict)
        ctx.obj["FORMAT"] = "json"  # TODO - investigate if we need yaml format.
    session = CommunityComponentService.create_session()
    if component_uuid:
        data = session.components.retrieve_manifest(component_uuid)
        return cprint(data, ctx=ctx)
    else:
        c = session.components.retrieve_list(purl=purl)
        if c:
            data = session.components.retrieve_manifest(c["uuid"])
            return cprint(data, ctx=ctx)


# PRODUCT STREAM
@commmunity_components_grp.group(help=f"{CORGI_API_URL}/api/v1/product_streams")
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
@query_params_options(
    entity="ProductStream",
    endpoint_module=v1_product_streams_list,
    options_overrides={
        "include_fields": {
            "type": click.Choice(CommunityComponentService.get_fields(ProductStream))
        },
    },
)
@click.pass_context
def list_product_streams(ctx, product_stream_name, **params):
    """Retrieve a list of Product Streams."""
    is_params_empty = [False for v in params.values() if v]
    if not product_stream_name and not is_params_empty:
        click.echo(ctx.get_help())
        exit(0)
    session = CommunityComponentService.create_session()
    if not params["include_fields"]:
        params["include_fields"] = "link,uuid,ofuri,name"

    if product_stream_name:
        params["re_name"] = product_stream_name
    return cprint(
        list(session.product_streams.retrieve_list_iterator_async(max_results=5000, **params)),
        ctx=ctx,
    )


@product_streams.command(name="get")
@click.argument(
    "product_stream_name",
    required=False,
    type=click.STRING,
    shell_complete=get_product_stream_names,
)
@click.option("--inactive", is_flag=True, default=False, help="Show inactive project streams")
@click.option("--ofuri", "ofuri", type=click.STRING, shell_complete=get_product_stream_ofuris)
@query_params_options(
    entity="ProductStream",
    endpoint_module=v1_product_streams_retrieve,
    options_overrides={
        "include_fields": {
            "type": click.Choice(CommunityComponentService.get_fields(ProductStream))
        },
    },
)
@click.pass_context
@progress_bar
def get_product_stream(ctx, product_stream_name, inactive, ofuri, **params):
    """Retrieve Product Stream."""
    is_params_empty = [False for v in params.values() if v]
    if not product_stream_name and not is_params_empty:
        click.echo(ctx.get_help())
        exit(0)
    session = CommunityComponentService.create_session()
    if ofuri:
        params["ofuri"] = ofuri
    if product_stream_name:
        params["name"] = product_stream_name
    data = session.product_streams.retrieve_list(**params)
    return cprint(data, ctx=ctx)


@product_streams.command(name="latest-components")
@click.argument(
    "product_stream_name",
    required=False,
    type=click.STRING,
    shell_complete=get_product_stream_names,
)
@click.option("--ofuri", "ofuri", type=click.STRING, shell_complete=get_product_stream_ofuris)
@query_params_options(
    entity="Component",
    endpoint_module=v1_components_list,
    options_overrides={
        "include_fields": {"type": click.Choice(CommunityComponentService.get_fields(Component))},
    },
)
@click.pass_context
def get_product_stream_components(ctx, product_stream_name, ofuri, **params):
    """Retrieve Product Stream latest Components."""
    if not ofuri and not product_stream_name:
        click.echo(ctx.get_help())
        exit(0)
    if not params["include_fields"]:
        params[
            "include_fields"
        ] = "link,uuid,purl,nvr,version,type,name,upstreams,related_url,download_url"

    if product_stream_name:
        session = CommunityComponentService.create_session()
        ps = session.product_streams.retrieve_list(name=product_stream_name)
        params["ofuri"] = ps["ofuri"]
    if ofuri:
        params["ofuri"] = ofuri
    ctx.invoke(list_components, **params)


@product_streams.command(name="manifest")
@click.argument(
    "product_stream_name",
    required=False,
    type=click.STRING,
    shell_complete=get_product_stream_names,
)
@click.option("--ofuri", "ofuri", type=click.STRING, shell_complete=get_product_stream_ofuris)
@click.option(
    "--spdx-json",
    "spdx_json_format",
    is_flag=True,
    default=False,
    help="Generate spdx manifest (json).",
)
@click.pass_context
@progress_bar
def get_product_stream_manifest(ctx, product_stream_name, ofuri, spdx_json_format):
    """Retrieve Product Stream manifest."""
    if not ofuri and not product_stream_name:
        click.echo(ctx.get_help())
        exit(0)
    session = CommunityComponentService.create_session()
    if spdx_json_format:
        ctx.ensure_object(dict)
        ctx.obj["FORMAT"] = "json"  # TODO - investigate if we need yaml format.
    ps = None
    if ofuri:
        ps = session.product_streams.retrieve_list(ofuri=ofuri).additional_properties
    if product_stream_name:
        ps = session.product_streams.retrieve_list(name=product_stream_name).additional_properties
    if not ps:
        logger.warning("could not find active product stream.")
    data = requests.get(ps["manifest"])
    cprint(data.json(), ctx=ctx)


# BUILDS


@commmunity_components_grp.group(help=f"{CORGI_API_URL}/api/v1/builds")
@click.pass_context
def builds(ctx):
    pass


@builds.command(name="list")
@click.argument("software_build_name", required=False)
@query_params_options(
    entity="SoftwareBuild",
    endpoint_module=v1_builds_list,
    options_overrides={
        "include_fields": {
            "type": click.Choice(CommunityComponentService.get_fields(SoftwareBuild))
        },
    },
)
@click.pass_context
def list_software_builds(ctx, software_build_name, **params):
    """Retrieve a list of Software Builds."""
    session = CommunityComponentService.create_session()
    if software_build_name:
        params["name"] = software_build_name
    return cprint(
        list(session.builds.retrieve_list_iterator_async(max_results=5000, **params)), ctx=ctx
    )


@builds.command(name="get")
@click.argument(
    "software_build_name",
    required=False,
    type=click.STRING,
    shell_complete=get_product_stream_names,
)
@query_params_options(
    entity="SoftwareBuild",
    endpoint_module=v1_builds_retrieve,
    options_overrides={
        "include_fields": {
            "type": click.Choice(CommunityComponentService.get_fields(SoftwareBuild))
        },
    },
)
@click.pass_context
@progress_bar
def get_software_build(ctx, software_build_name, **params):
    """Retrieve SoftwareBuild."""
    is_params_empty = [False for v in params.values() if v]
    if not software_build_name and not is_params_empty:
        click.echo(ctx.get_help())
        exit(0)
    session = CommunityComponentService.create_session()
    if software_build_name:
        params["name"] = software_build_name
    data = session.builds.retrieve_list(**params)
    return cprint(data, ctx=ctx)


# Products


@commmunity_components_grp.group(help=f"{CORGI_API_URL}/api/v1/products")
@click.pass_context
def products(ctx):
    pass


@products.command(name="list")
@click.argument("product_name", required=False)
@query_params_options(
    entity="Product",
    endpoint_module=v1_products_list,
    options_overrides={
        "include_fields": {"type": click.Choice(CommunityComponentService.get_fields(Product))},
    },
)
@click.pass_context
@progress_bar
def list_products(ctx, product_name, **params):
    """Retrieve a list of Software Builds."""
    session = CommunityComponentService.create_session()
    if product_name:
        params["re_name"] = product_name
    return cprint(
        list(session.products.retrieve_list_iterator_async(max_results=5000, **params)), ctx=ctx
    )


@products.command(name="get")
@click.argument(
    "product_name",
    required=False,
    type=click.STRING,
    shell_complete=get_product_stream_names,
)
@click.option("--ofuri", "ofuri", type=click.STRING, shell_complete=get_product_stream_ofuris)
@query_params_options(
    entity="Product",
    endpoint_module=v1_products_retrieve,
    options_overrides={
        "include_fields": {"type": click.Choice(CommunityComponentService.get_fields(Product))},
    },
)
@click.pass_context
@progress_bar
def get_product(ctx, product_name, ofuri, **params):
    """Retrieve Product."""
    is_params_empty = [False for v in params.values() if v]
    if not product_name and not is_params_empty:
        click.echo(ctx.get_help())
        exit(0)
    session = CommunityComponentService.create_session()
    if ofuri:
        params["ofuri"] = ofuri
    if product_name:
        params["name"] = product_name
    data = session.products.retrieve_list(**params)
    return cprint(data, ctx=ctx)


# PRODUCT VERSION
@commmunity_components_grp.group(help=f"{CORGI_API_URL}/api/v1/product-versions")
@click.pass_context
def product_versions(ctx):
    pass


@product_versions.command(name="list")
@click.argument("product_version_name", required=False)
@query_params_options(
    entity="ProductVersion",
    endpoint_module=v1_product_versions_list,
    options_overrides={
        "include_fields": {
            "type": click.Choice(CommunityComponentService.get_fields(ProductVersion))
        },
    },
)
@click.pass_context
@progress_bar
def list_product_versions(ctx, product_version_name, **params):
    """Retrieve a list of Product Versions."""
    session = CommunityComponentService.create_session()
    if product_version_name:
        params["re_name"] = product_version_name
    return cprint(
        list(session.product_versions.retrieve_list_iterator_async(max_results=5000, **params)),
        ctx=ctx,
    )


@product_versions.command(name="get")
@click.argument(
    "product_version_name",
    required=False,
    type=click.STRING,
    shell_complete=get_product_stream_names,
)
@click.option("--ofuri", "ofuri", type=click.STRING, shell_complete=get_product_version_ofuris)
@query_params_options(
    entity="ProductVersion",
    endpoint_module=v1_product_versions_retrieve,
    options_overrides={
        "include_fields": {
            "type": click.Choice(CommunityComponentService.get_fields(ProductVersion))
        },
    },
)
@click.pass_context
@progress_bar
def get_product_version(ctx, product_version_name, ofuri, **params):
    """Retrieve ProductVersion."""
    is_params_empty = [False for v in params.values() if v]
    if not product_version_name and not is_params_empty:
        click.echo(ctx.get_help())
        exit(0)
    session = CommunityComponentService.create_session()
    if ofuri:
        params["ofuri"] = ofuri
    if product_version_name:
        params["name"] = product_version_name
    data = session.product_versions.retrieve_list(**params)
    return cprint(data, ctx=ctx)


# PRODUCT VARIANT
@commmunity_components_grp.group(help=f"{CORGI_API_URL}/api/v1/product-variants")
@click.pass_context
def product_variants(ctx):
    pass


@product_variants.command(name="list")
@click.argument("product_variant_name", required=False)
@query_params_options(
    entity="ProductVariant",
    endpoint_module=v1_product_variants_list,
    options_overrides={
        "include_fields": {
            "type": click.Choice(CommunityComponentService.get_fields(ProductVariant))
        },
    },
)
@click.pass_context
@progress_bar
def list_product_variants(ctx, product_variant_name, **params):
    """Retrieve a list of Product Variants."""
    session = CommunityComponentService.create_session()
    if product_variant_name:
        params["re_name"] = product_variant_name
    return cprint(
        list(session.product_variants.retrieve_list_iterator_async(max_results=5000, **params)),
        ctx=ctx,
    )


@product_variants.command(name="get")
@click.argument(
    "product_variant_name",
    required=False,
    type=click.STRING,
    shell_complete=get_product_stream_names,
)
@click.option("--ofuri", "ofuri", type=click.STRING, shell_complete=get_product_version_ofuris)
@query_params_options(
    entity="ProductVariant",
    endpoint_module=v1_product_variants_retrieve,
    options_overrides={
        "include_fields": {
            "type": click.Choice(CommunityComponentService.get_fields(ProductVariant))
        },
    },
)
@click.pass_context
@progress_bar
def get_product_variant(ctx, product_variant_name, ofuri, **params):
    """Retrieve ProductVariant."""
    is_params_empty = [False for v in params.values() if v]
    if not product_variant_name and not is_params_empty:
        click.echo(ctx.get_help())
        exit(0)
    session = CommunityComponentService.create_session()
    if ofuri:
        params["ofuri"] = ofuri
    if product_variant_name:
        params["name"] = product_variant_name
    data = session.product_varints.retrieve_list(**params)
    return cprint(data, ctx=ctx)


# CHANNEL
@commmunity_components_grp.group(help=f"{CORGI_API_URL}/api/v1/channels")
@click.pass_context
def channels(ctx):
    pass


@channels.command(name="list")
@click.argument("channel_name", required=False)
@query_params_options(
    entity="Channel",
    endpoint_module=v1_channels_list,
    options_overrides={
        "include_fields": {"type": click.Choice(CommunityComponentService.get_fields(Channel))},
    },
)
@click.pass_context
@progress_bar
def list_channels(ctx, channel_name, **params):
    """Retrieve a list of Channels."""
    session = CommunityComponentService.create_session()
    if channel_name:
        params["re_name"] = channel_name
    return cprint(
        list(session.channels.retrieve_list_iterator_async(max_results=5000, **params)), ctx=ctx
    )


@channels.command(name="get")
@click.argument(
    "channel_name",
    required=False,
    type=click.STRING,
    shell_complete=get_product_stream_names,
)
@click.option("--ofuri", "ofuri", type=click.STRING, shell_complete=get_product_version_ofuris)
@query_params_options(
    entity="Channel",
    endpoint_module=v1_channels_retrieve,
    options_overrides={
        "include_fields": {"type": click.Choice(CommunityComponentService.get_fields(Channel))},
    },
)
@click.pass_context
@progress_bar
def get_channel(ctx, channel_name, ofuri, **params):
    """Retrieve ProductVariant."""
    is_params_empty = [False for v in params.values() if v]
    if not channel_name and not is_params_empty:
        click.echo(ctx.get_help())
        exit(0)
    session = CommunityComponentService.create_session()
    if ofuri:
        params["ofuri"] = ofuri
    if channel_name:
        params["name"] = channel_name
    data = session.channels.retrieve_list(**params)
    return cprint(data, ctx=ctx)


# ADMIN
@commmunity_components_grp.group(name="admin")
@click.pass_context
def manage_grp(ctx):
    """Manage component registry"""
    pass


@manage_grp.command(name="status")
@click.pass_context
def corgi_status(ctx):
    session = CommunityComponentService.create_session()
    data = session.status()
    return cprint(data.additional_properties, ctx=ctx)


@manage_grp.command(name="health")
@click.pass_context
def corgi_health(ctx):
    try:
        session = CommunityComponentService.create_session()
        status = session.status()["status"]
        if status == "ok":
            console.log(f"{CORGI_API_URL} is operational")
        else:
            console.log(f"{CORGI_API_URL} is NOT operational")
            exit(1)
    except:  # noqa
        console.log(f"{CORGI_API_URL} is NOT operational")
        raise click.ClickException("Component registry health check failed.")


@manage_grp.command(name="data")
def corgi_data():
    click.launch(f"{CORGI_API_URL}/data")


@manage_grp.command(name="api_doc")
def corgi_api_docs():
    click.launch(f"{CORGI_API_URL}/api/v1/schema/docs")
