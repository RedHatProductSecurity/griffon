"""

"""
import logging

import click

from griffon import CorgiService, OSIDBService, progress_bar
from griffon.autocomplete import get_cve_ids, get_product_version_names
from griffon.commands.entities import (
    get_component_manifest,
    get_component_summary,
    get_product_stream_manifest,
    get_product_stream_names,
    get_product_stream_ofuris,
    list_components,
)
from griffon.commands.process import generate_affects_for_component_process
from griffon.commands.reports import generate_affects_report
from griffon.output import cprint
from griffon.services import QueryService, core_queries  # , exp

logger = logging.getLogger("griffon")

query_service = QueryService()


@click.group(name="service", help="Service operations.")
@click.pass_context
def queries_grp(ctx):
    """Query operations."""
    pass


queries_grp.add_command(generate_affects_report)
queries_grp.add_command(generate_affects_for_component_process)


@queries_grp.command(
    name="product-summary",
    help="Get Product summaries.",
)
@click.argument(
    "product_stream_name",
    required=False,
    type=click.STRING,
    shell_complete=get_product_stream_names,
)
# TODO - underlying bindings need to support 'ofuri'
# @click.option(
#     "--ofuri",
#     "ofuri",
#     type=click.STRING,
#     shell_complete=get_product_stream_ofuris,
#     help="UNDER DEVELOPMENT",
# )
@click.option(
    "-s",
    "strict_name_search",
    is_flag=True,
    default=False,
    help="Strict search, exact match of name.",
)
@click.pass_context
@progress_bar
def get_product_summary(ctx, product_stream_name, strict_name_search):
    """get product stream."""
    if not product_stream_name:
        click.echo(ctx.get_help())
        exit(0)
    q = query_service.invoke(core_queries.product_stream_summary, ctx.params)
    cprint(q, ctx=ctx)


@queries_grp.command(
    name="component-summary",
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
def retrieve_component_summary(ctx, component_name, strict_name_search):
    """Get Component summary."""
    if not component_name:
        click.echo(ctx.get_help())
        exit(0)
    cond = {}
    if component_name:
        cond["component_name"] = component_name
    ctx.invoke(get_component_summary, **cond)


@queries_grp.command(
    name="products-contain-component",
    help="List Products containing Component.",
)
@click.argument("component_name", required=False)
@click.option(
    "--purl", help="Component purl, needs to be in quotes (ex. 'pkg:rpm/python-pyjwt@1.7.1')"
)
@click.option(
    "--arch",
    default="src",
    type=click.Choice(CorgiService.get_component_arches()),
)
@click.option(
    "--namespace", default=None, type=click.Choice(CorgiService.get_component_namespaces())
)
@click.option("--type", "component_type", type=click.Choice(CorgiService.get_component_types()))
@click.option(
    "-s",
    "strict_name_search",
    is_flag=True,
    default=False,
    help="Strict search, exact match of component name.",
)
@click.option(
    "--affect-mode",
    "-a",
    "affect_mode",
    is_flag=True,
    default=False,
    help="Generate Affects.",
)
@click.option(
    "--search-latest",
    "search_latest",
    is_flag=True,
    default=False,
    help="Search root Components (enabled by default).",
)
@click.option(
    "--search-related-url",
    "search_related_url",
    is_flag=True,
    default=False,
    help="Search related url (enabled by default).",
)
@click.option(
    "--search-all",
    "search_all",
    is_flag=True,
    default=False,
    help="Search root Components and dependencies.",
)
@click.option(
    "--search-community",
    "search_community",
    is_flag=True,
    default=False,
    help="(Not Implemented) Search community Components.",
)
@click.option(
    "--search-upstreams",
    "search_upstreams",
    is_flag=True,
    default=False,
    help="Search for Components by upstream.",
)
@click.pass_context
@progress_bar
def get_product_contain_component(
    ctx,
    component_name,
    purl,
    arch,
    namespace,
    component_type,
    strict_name_search,
    affect_mode,
    search_latest,
    search_related_url,
    search_all,
    search_community,
    search_upstreams,
):
    """List products of a latest component."""
    if not purl and not component_name:
        click.echo(ctx.get_help())
        click.echo("")
        click.echo("Must supply Component name or --purl.")
        exit(0)

    if (
        not search_latest
        and not search_all
        and not search_related_url
        and not search_community
        and not search_upstreams
    ):
        ctx.params["search_latest"] = True
        ctx.params["search_related_url"] = True

    if component_name:
        q = query_service.invoke(core_queries.products_containing_component_query, ctx.params)
        cprint(q, ctx=ctx)
    if purl:
        q = query_service.invoke(
            core_queries.products_containing_specific_component_query, ctx.params
        )
        cprint(q, ctx=ctx)


@queries_grp.command(
    name="components-contain-component",
    help="List Components containing Component.",
)
@click.argument("component_name", required=False)
@click.option("--purl")
@click.option("--type", "component_type", type=click.Choice(CorgiService.get_component_types()))
@click.option("--version", "component_version")
@click.option(
    "--arch",
    "component_arch",
    type=click.Choice(CorgiService.get_component_arches()),
    help="Default arch=src.",
)
@click.option("--namespace", type=click.Choice(CorgiService.get_component_namespaces()))
@click.option(
    "-s",
    "strict_name_search",
    is_flag=True,
    default=False,
    help="Strict search, exact match of component name.",
)
@click.pass_context
@progress_bar
def get_component_contain_component(
    ctx,
    component_name,
    purl,
    component_type,
    component_version,
    component_arch,
    namespace,
    strict_name_search,
):
    """List components that contain component."""
    if not component_name and not purl:
        click.echo(ctx.get_help())
        exit(0)
    if component_name:
        q = query_service.invoke(core_queries.components_containing_component_query, ctx.params)
        cprint(q, ctx=ctx)
    if purl:
        q = query_service.invoke(
            core_queries.components_containing_specific_component_query, ctx.params
        )
        cprint(q, ctx=ctx)


@queries_grp.command(
    name="product-manifest",
    help="Get Product manifest (includes Root Components and all dependencies).",
)
@click.argument("product_stream_name", required=False, shell_complete=get_product_stream_names)
@click.option("--ofuri", "ofuri", type=click.STRING, shell_complete=get_product_stream_ofuris)
@click.option(
    "--spdx-json",
    "spdx_json_format",
    is_flag=True,
    default=False,
    help="Generate spdx manifest (json).",
)
@click.pass_context
def get_product_manifest_query(ctx, product_stream_name, ofuri, spdx_json_format):
    """List components of a specific product version."""
    if not ofuri and not product_stream_name:
        click.echo(ctx.get_help())
        exit(0)

    if spdx_json_format:
        ctx.ensure_object(dict)
        ctx.obj["FORMAT"] = "json"  # TODO - investigate if we need yaml format.

    cond = {}
    if ofuri:
        cond["ofuri"] = ofuri
    if product_stream_name:
        cond["product_stream_name"] = product_stream_name
    ctx.invoke(get_product_stream_manifest, **cond)


@queries_grp.command(
    name="product-components",
    help="List LATEST Root Components of Product.",
)
@click.pass_context
@click.argument("product_stream_name", required=False, shell_complete=get_product_stream_names)
@click.option("--ofuri", "ofuri", type=click.STRING, shell_complete=get_product_stream_ofuris)
def get_product_latest_components_query(ctx, product_stream_name, ofuri):
    """List components of a specific product version."""
    if not ofuri and not product_stream_name:
        click.echo(ctx.get_help())
        exit(0)
    cond = {}
    if ofuri:
        cond["ofuri"] = ofuri
    if product_stream_name:
        # lookup ofuri
        q = query_service.invoke(core_queries.product_stream_summary, ctx.params)
        ofuri = q[0]["ofuri"]
        cond["ofuri"] = ofuri
    ctx.invoke(list_components, **cond)


@queries_grp.command(
    name="component-manifest",
    help="Get Component manifest.",
)
@click.option("--uuid", "component_uuid")
@click.option("--purl", help="Component Purl (must be quoted).")
@click.option(
    "--spdx-json",
    "spdx_json_format",
    is_flag=True,
    default=False,
    help="Generate spdx manifest (json).",
)
@click.pass_context
def retrieve_component_manifest(ctx, component_uuid, purl, spdx_json_format):
    """Retrieve Component manifest."""
    if not component_uuid and not purl:
        click.echo(ctx.get_help())
        exit(0)
    if spdx_json_format:
        ctx.ensure_object(dict)
        ctx.obj["FORMAT"] = "json"
    cond = {}
    if component_uuid:
        cond["uuid"] = component_uuid
    if purl:
        cond["purl"] = purl
    ctx.invoke(get_component_manifest, **cond)


@queries_grp.command(
    name="components-affected-by-flaw",
    help="List Components affected by Flaw.",
)
@click.argument("cve_id", required=False, type=click.STRING, shell_complete=get_cve_ids)
@click.option(
    "--affectedness",
    help="Filter by Affect affectedness.",
    type=click.Choice(OSIDBService.get_affect_affectedness()),
)
@click.option(
    "--resolution",
    "affect_resolution",
    help="Filter by Affect resolution.",
    type=click.Choice(OSIDBService.get_affect_resolution()),
)
@click.option(
    "--impact",
    "affect_impact",
    help="Filter by Affect impact.",
    type=click.Choice(OSIDBService.get_affect_impact()),
)
@click.option(
    "--type",
    "component_type",
    type=click.Choice(CorgiService.get_component_types()),
    help="Filter by Component type.",
)
@click.option(
    "--namespace",
    type=click.Choice(CorgiService.get_component_namespaces()),
    help="filter by Component namespace.",
)
@click.pass_context
@progress_bar
def components_affected_by_specific_cve_query(
    ctx, cve_id, affectedness, affect_resolution, affect_impact, component_type, namespace
):
    """List components affected by specific CVE."""
    if not cve_id:
        click.echo(ctx.get_help())
        exit(0)
    q = query_service.invoke(core_queries.components_affected_by_specific_cve_query, ctx.params)
    cprint(q, ctx=ctx)


@queries_grp.command(
    name="products-affected-by-flaw",
    help="List Products affected by Flaw.",
)
@click.argument("cve_id", required=False, type=click.STRING, shell_complete=get_cve_ids)
@click.pass_context
@progress_bar
def product_versions_affected_by_cve_query(ctx, cve_id):
    """List Products affected by a CVE."""
    if not cve_id:
        click.echo(ctx.get_help())
        exit(0)
    q = query_service.invoke(
        core_queries.products_versions_affected_by_specific_cve_query, ctx.params
    )
    cprint(q, ctx=ctx)


@queries_grp.command(name="component-flaws", help="List Flaws affecting a Component.")
@click.argument("component_name", required=False)
@click.option("--purl")
@click.option(
    "--flaw-state",
    "flaw_state",
    help="Filter by Flaw state.",
    type=click.Choice(OSIDBService.get_flaw_states()),
)
@click.option(
    "--flaw-impact",
    "flaw_impact",
    help="Filter by Flaw impact.",
    type=click.Choice(OSIDBService.get_flaw_impacts()),
)
@click.option(
    "--flaw-resolution",
    "flaw_resolution",
    help="Filter by Flaw resolution.",
    type=click.Choice(OSIDBService.get_flaw_resolutions()),
)
@click.option(
    "--affectedness",
    help="Filter by Affect affectedness.",
    type=click.Choice(OSIDBService.get_affect_affectedness()),
)
@click.option(
    "--affect-resolution",
    "affect_resolution",
    help="Filter by Affect resolution.",
    type=click.Choice(OSIDBService.get_affect_resolution()),
)
@click.option(
    "--affect-impact",
    "affect_impact",
    help="Filter by Affect impact.",
    type=click.Choice(OSIDBService.get_affect_impact()),
)
@click.option(
    "-s",
    "strict_name_search",
    is_flag=True,
    default=False,
    help="Strict search, exact match of component name.",
)
@click.pass_context
@progress_bar
def cves_for_specific_component_query(
    ctx,
    component_name,
    purl,
    flaw_state,
    flaw_impact,
    flaw_resolution,
    affectedness,
    affect_resolution,
    affect_impact,
    strict_name_search,
):
    """List flaws of a specific component."""
    if not purl and not component_name:
        click.echo(ctx.get_help())
        exit(0)

    q = query_service.invoke(core_queries.cves_for_specific_component_query, ctx.params)
    cprint(q, ctx=ctx)


@queries_grp.command(
    name="product-flaws",
    help="List Flaws affecting a Product.",
)
@click.argument(
    "product_version_name",
    required=False,
    type=click.STRING,
    shell_complete=get_product_version_names,
)
@click.option("--ofuri")
@click.option(
    "--flaw-state",
    "flaw_state",
    help="Filter by Flaw state.",
    type=click.Choice(OSIDBService.get_flaw_states()),
)
@click.option(
    "--flaw-impact",
    "flaw_impact",
    help="Filter by Flaw impact.",
    type=click.Choice(OSIDBService.get_flaw_impacts()),
)
@click.option(
    "--flaw-resolution",
    "flaw_resolution",
    help="Filter by Flaw resolution.",
    type=click.Choice(OSIDBService.get_flaw_resolutions()),
)
@click.option(
    "--affectedness",
    help="Filter by Affect affectedness.",
    type=click.Choice(OSIDBService.get_affect_affectedness()),
)
@click.option(
    "--affect-resolution",
    "affect_resolution",
    help="Filter by Affect resolution.",
    type=click.Choice(OSIDBService.get_affect_resolution()),
)
@click.option(
    "--affect-impact",
    "affect_impact",
    help="Filter by Affect impact.",
    type=click.Choice(OSIDBService.get_affect_impact()),
)
@click.option(
    "-s",
    "strict_name_search",
    is_flag=True,
    default=False,
    help="Strict search, exact match of component name.",
)
@click.pass_context
def cves_for_specific_product_query(
    ctx,
    product_version_name,
    ofuri,
    flaw_state,
    flaw_impact,
    flaw_resolution,
    affectedness,
    affect_impact,
    affect_resolution,
    strict_name_search,
):
    """List flaws of a specific product."""
    if not product_version_name and not ofuri:
        click.echo(ctx.get_help())
        exit(0)
    q = query_service.invoke(core_queries.cves_for_specific_product_query, ctx.params)
    cprint(q, ctx=ctx)
