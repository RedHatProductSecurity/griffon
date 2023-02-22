"""

"""
import logging

import click

from griffon import CorgiService, OSIDBService, progress_bar
from griffon.autocomplete import get_cve_ids, get_product_version_names
from griffon.commands.entities import (
    get_component_manifest,
    get_product_stream_manifest,
    get_product_stream_names,
    get_product_stream_ofuris,
    list_components,
)
from griffon.commands.process import generate_affects_for_component_process
from griffon.commands.reports import generate_affects_report
from griffon.output import cprint
from griffon.services import QueryService, core_queries  # , exp

logger = logging.getLogger("rich")

query_service = QueryService()


@click.group(name="service", help="Service operations.")
@click.pass_context
def queries_grp(ctx):
    """Query operations."""
    pass


queries_grp.add_command(generate_affects_report)
queries_grp.add_command(generate_affects_for_component_process)


@queries_grp.command(
    name="products-contain-component",
    help="List Products containing Component.",
)
@click.option("--re-name", "component_re_name", help="Search name by regex.")
@click.option("--name", "component_name")
@click.option("--purl")
@click.option(
    "--arch",
    default="src",
    type=click.Choice(CorgiService.get_component_arches()),
    help="Default arch=src.",
)
@click.option(
    "--namespace", default=None, type=click.Choice(CorgiService.get_component_namespaces())
)
@click.option("--type", "component_type", type=click.Choice(CorgiService.get_component_types()))
@click.pass_context
@progress_bar
def get_product_contain_component(
    ctx, component_re_name, component_name, purl, arch, namespace, component_type
):
    """List components of a product version."""
    if not purl and not component_name and not component_re_name:
        click.echo(ctx.get_help())
        click.echo("")
        click.echo("Must supply --name or --purl.")
        exit(0)
    if component_name or component_re_name:
        q = query_service.invoke(core_queries.products_containing_component_query, ctx.params)
        cprint(q, ctx=ctx)
    if purl:
        q = query_service.invoke(
            core_queries.products_containing_specific_component_query, ctx.params
        )
        cprint(q, ctx=ctx)


@queries_grp.command(
    name="components-contain-component",
    help="List Components contain component.",
)
@click.option("--re-name", "component_re_name", help="Search name by regex.")
@click.option("--name", "component_name")
@click.option("--purl")
@click.option("--type", "component_type", type=click.Choice(CorgiService.get_component_types()))
@click.option("--namespace", type=click.Choice(CorgiService.get_component_namespaces()))
@click.pass_context
@progress_bar
def get_component_contain_component(
    ctx, component_re_name, component_name, purl, component_type, namespace
):
    """List components that contain component."""
    if not purl and not component_name and not component_re_name:
        click.echo(ctx.get_help())
        exit(0)
    if component_name or component_re_name:
        q = query_service.invoke(core_queries.components_containing_component_query, ctx.params)
        cprint(
            q,
            ctx=ctx,
        )
    if purl:
        q = query_service.invoke(
            core_queries.components_containing_specific_component_query, ctx.params
        )
        cprint(
            q,
            ctx=ctx,
        )


@queries_grp.command(
    name="product-summary",
    help="Get Product summary.",
)
@click.option("--inactive", is_flag=True, default=False, help="Show inactive project streams")
@click.option(
    "--ofuri",
    "ofuri",
    type=click.STRING,
    shell_complete=get_product_stream_ofuris,
    help="UNDER DEVELOPMENT",
)
@click.option(
    "--re-name",
    "product_stream_re_name",
    type=click.STRING,
    shell_complete=get_product_stream_names,
)
@click.option(
    "--name", "product_stream_name", type=click.STRING, shell_complete=get_product_stream_names
)
@click.pass_context
@progress_bar
def get_product_query(ctx, inactive, ofuri, product_stream_re_name, product_stream_name):
    """get product stream."""
    if not product_stream_name and not ofuri or not product_stream_re_name:
        click.echo(ctx.get_help())
        exit(0)
    q = query_service.invoke(core_queries.product_stream_summary, ctx.params)
    cprint(q, ctx=ctx)


@queries_grp.command(
    name="product-manifest",
    help="Get Product manifest.",
)
@click.option("--ofuri", "ofuri", type=click.STRING, shell_complete=get_product_stream_ofuris)
@click.option(
    "--name", "product_stream_name", type=click.STRING, shell_complete=get_product_stream_names
)
@click.pass_context
def get_product_manifest_query(ctx, ofuri, product_stream_name):
    """List components of a specific product version."""
    if not ofuri and not product_stream_name:
        click.echo(ctx.get_help())
        exit(0)
    cond = {}
    if ofuri:
        cond["ofuri"] = ofuri
    if product_stream_name:
        cond["product_stream_name"] = product_stream_name
    ctx.invoke(get_product_stream_manifest, **cond)


@queries_grp.command(
    name="product-components",
    help="List LATEST Components of Product.",
)
@click.option("--ofuri", "ofuri", type=click.STRING, shell_complete=get_product_stream_ofuris)
@click.option(
    "--name", "product_stream_name", type=click.STRING, shell_complete=get_product_stream_names
)
@click.pass_context
def get_product_latest_components_query(ctx, ofuri, product_stream_name):
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
        ofuri = q["ofuri"]
        cond["ofuri"] = ofuri
    ctx.invoke(list_components, **cond)


@queries_grp.command(
    name="product-all-components",
    help="List ALL Components of Product.",
)
@click.option("--ofuri", "ofuri", type=click.STRING, shell_complete=get_product_stream_ofuris)
@click.option(
    "--name", "product_stream_name", type=click.STRING, shell_complete=get_product_stream_names
)
@click.pass_context
def get_product_all_components_query(ctx, ofuri, product_stream_name):
    """List components of a specific product stream."""
    if not ofuri and not product_stream_name:
        click.echo(ctx.get_help())
        exit(0)
    cond = {}
    if ofuri:
        cond["product_stream_ofuri"] = ofuri
    if product_stream_name:
        # lookup ofuri
        q = query_service.invoke(core_queries.product_stream_summary, ctx.params)
        ofuri = q["ofuri"]
        cond["product_stream_ofuri"] = ofuri
    ctx.invoke(list_components, **cond)


@queries_grp.command(
    name="component-manifest",
    help="Get Component manifest.",
)
@click.option("--uuid", "component_uuid")
@click.option("--purl", help="Purl are URI and must be quoted.")
@click.pass_context
def retrieve_component_manifest(ctx, component_uuid, purl):
    """Retrieve component manifest."""
    if not component_uuid and not purl:
        click.echo(ctx.get_help())
        exit(0)
    cond = {}
    if component_uuid:
        cond["component_uuid"] = component_uuid
    if purl:
        cond["purl"] = purl
    ctx.invoke(get_component_manifest, **cond)


@queries_grp.command(
    name="components-affected-by-flaw",
    help="List Components affected by Flaw.",
)
@click.option("--cve-id", shell_complete=get_cve_ids)
@click.option(
    "--affectedness",
    help="Filter by affect affectedness.",
    type=click.Choice(OSIDBService.get_affect_affectedness()),
)
@click.option(
    "--resolution",
    "affect_resolution",
    help="Filter by affect resolution.",
    type=click.Choice(OSIDBService.get_affect_resolution()),
)
@click.option(
    "--impact",
    "affect_impact",
    help="Filter by affect impact.",
    type=click.Choice(OSIDBService.get_affect_impact()),
)
@click.option(
    "--type",
    "component_type",
    type=click.Choice(CorgiService.get_component_types()),
    help="Filter by component type.",
)
@click.option(
    "--namespace",
    type=click.Choice(CorgiService.get_component_namespaces()),
    help="filter by component namespace.",
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
    cprint(
        q,
        ctx=ctx,
    )


@queries_grp.command(
    name="products-affected-by-cve",
    help="List Products affected by CVE.",
)
@click.option("--cve-id", shell_complete=get_cve_ids)
@click.pass_context
@progress_bar
def product_versions_affected_by_cve_query(ctx, cve_id):
    """List products affected by a CVE."""
    if not cve_id:
        click.echo(ctx.get_help())
        exit(0)
    q = query_service.invoke(
        core_queries.products_versions_affected_by_specific_cve_query, ctx.params
    )
    cprint(q, ctx=ctx)


@queries_grp.command(name="flaws-component", help="(UNDER DEV) List Flaws affecting a Component.")
@click.option("--purl")
@click.option("--affectedness")
@click.pass_context
@progress_bar
def cves_for_specific_component_query(ctx, purl, affectedness):
    """List cves of a specific component."""
    if not purl:
        click.echo(ctx.get_help())
        exit(0)
    q = query_service.invoke(core_queries.cves_for_specific_component_query, ctx.params)
    cprint(q, ctx=ctx)


@queries_grp.command(
    name="flaws-product",
    help="(UNDER DEV) List Flaws affecting a Product.",
)
@click.option(
    "--re-name",
    "product_version_re_name",
    help="product_version name (eg. ps_module)",
    shell_complete=get_product_version_names,
)
@click.option(
    "--name",
    "product_version_name",
    help="product_version name (eg. ps_module)",
    shell_complete=get_product_version_names,
)
@click.option("--affectedness", type=click.Choice(OSIDBService.get_affect_affectedness()))
@click.option("--affect-impact", type=click.Choice(OSIDBService.get_flaw_impacts()))
@click.option("--affect-resolution", type=click.Choice(OSIDBService.get_affect_resolution()))
@click.option("--flaw-state", type=click.Choice(OSIDBService.get_flaw_states()))
@click.option("--flaw-resolution", type=click.Choice(OSIDBService.get_flaw_resolutions()))
@click.pass_context
def cves_for_specific_product_query(
    ctx,
    product_version_re_name,
    product_version_name,
    affectedness,
    affect_impact,
    affect_resolution,
    flaw_state,
    flaw_resolution,
):
    """List cves of a specific product."""
    if not product_version_name:
        click.echo(ctx.get_help())
        exit(0)
    q = query_service.invoke(core_queries.cves_for_specific_product_query, ctx.params)
    cprint(q, ctx=ctx)
