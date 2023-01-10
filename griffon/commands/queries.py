"""

"""
import logging

import click

from griffon.commands.entities import (
    get_product_stream_manifest,
    get_product_stream_names,
    get_product_stream_ofuris,
    list_components,
)
from griffon.output import console, cprint
from griffon.service_layer import Query, core_queries

logger = logging.getLogger("rich")


@click.group(name="queries", help="Service operations that are read only.")
@click.pass_context
def queries_grp(ctx):
    """Query operations."""
    pass


@queries_grp.group(name="core", help="(In development) Core queries.")
@click.pass_context
def core_grp(ctx):
    """Query operations."""
    pass


@core_grp.command(name="component_cves", help="List CVEs affecting a component.")
@click.option("--purl")
@click.option("--affectedness")
@click.pass_context
def cves_for_specific_component_query(ctx, purl, affectedness):
    """List cves of a specific component."""
    if not purl:
        click.echo(ctx.get_help())
        exit(0)
    with console.status("griffoning...", spinner="line"):
        q = core_queries.cves_for_specific_component_query()
        assert isinstance(q, Query)
        cprint(q.execute({"purl": purl, "affectedness": affectedness}))


@core_grp.command(
    name="components_affected_by_cve",
    help="List components affected by CVE.",
)
@click.option("--cve-id")
@click.pass_context
def components_affected_by_specific_cve_query(ctx, cve_id):
    """List unfixed cves of a specific component."""
    if not cve_id:
        click.echo(ctx.get_help())
        exit(0)
    with console.status("griffoning...", spinner="line"):
        q = core_queries.components_affected_by_specific_cve_query()
        assert isinstance(q, Query)
        cprint(q.execute({"cve_id": cve_id}))


@core_grp.command(
    name="cves_for_product_version",
    help="List CVEs of a product version.",
)
@click.option("--name", "product_version_name", help="product_version name (eg. ps_module)")
@click.option("--affectedness")
@click.option("--affect-impact")
@click.option("--affect-resolution")
@click.option("--flaw-state")
@click.option("--flaw-resolution")
@click.pass_context
def cves_for_specific_product_query(
    ctx,
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
    with console.status("griffoning...", spinner="line"):
        q = core_queries.cves_for_specific_product_query()
        assert isinstance(q, Query)
        cprint(
            q.execute(
                {
                    "product_version_name": product_version_name,
                    "affectedness": affectedness,
                    "affect_impact": affect_impact,
                    "affect_resolution": affect_resolution,
                    "flaw_state": flaw_state,
                    "flaw_resolution": flaw_resolution,
                }
            )
        )


# cves_for_product_stream_query


@core_grp.command(
    name="product_versions_affected_by_cve",
    help="List product versions affected by a CVE.",
)
@click.option("--cve-id")
@click.pass_context
def product_versions_affected_by_cve_query(ctx, cve_id):
    """List cves of a specific product."""
    if not cve_id:
        click.echo(ctx.get_help())
        exit(0)
    with console.status("griffoning...", spinner="line"):
        q = core_queries.products_versions_affected_by_specific_cve_query()
        cprint(q.execute({"cve_id": cve_id}))


@core_grp.command(
    name="components_in_product_stream",
    help="List components of product version.",
)
@click.option("--ofuri")
@click.option("--namespace", type=click.Choice(["REDHAT", "UPSTREAM"]), help="")
@click.pass_context
def components_in_product_stream_query(ctx, ofuri, namespace):
    """List components of a specific product version."""
    if not ofuri:
        click.echo(ctx.get_help())
        exit(0)
    # good example of invoking an existing command
    ctx.invoke(list_components, ofuri=ofuri)


@core_grp.command(
    name="products_containing_specific_component",
    help="List products of a specific component.",
)
@click.option("--purl")
@click.pass_context
def products_containing_specific_component_query(ctx, purl):
    """List components of a specific product version."""
    if not purl:
        click.echo(ctx.get_help())
        exit(0)
    with console.status("griffoning...", spinner="line"):
        q = core_queries.products_containing_specific_component_query()
        cprint(q.execute({"purl": purl}))


@queries_grp.command(
    name="get-product",
    help="(DEP1US7) Get product stream summary",
)
@click.option("--inactive", is_flag=True, default=False, help="Show inactive project streams")
@click.option("--ofuri", "ofuri", type=click.STRING, shell_complete=get_product_stream_ofuris)
@click.option(
    "--name", "product_stream_name", type=click.STRING, shell_complete=get_product_stream_names
)
@click.pass_context
def dep7_query(ctx, inactive, ofuri, product_stream_name):
    """List components of a specific product version."""
    if not product_stream_name and not ofuri:
        click.echo(ctx.get_help())
        exit(0)
    with console.status("griffoning...", spinner="line"):
        q = core_queries.dep_us7_query()
        cprint(q.execute(product_stream_name, ofuri))


@queries_grp.command(
    name="get-product-manifest",
    help="(DEP1US7) Get manifest",
)
@click.option("--ofuri", "ofuri", type=click.STRING, shell_complete=get_product_stream_ofuris)
@click.option(
    "--name", "product_stream_name", type=click.STRING, shell_complete=get_product_stream_names
)
@click.pass_context
def dep7_manifest_query(ctx, ofuri, product_stream_name):
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
    name="get-product-components",
    help="(DEP1US7) Get latest-components",
)
@click.option("--ofuri", "ofuri", type=click.STRING, shell_complete=get_product_stream_ofuris)
@click.option(
    "--name", "product_stream_name", type=click.STRING, shell_complete=get_product_stream_names
)
@click.pass_context
def dep7_latest_components_query(ctx, ofuri, product_stream_name):
    """List components of a specific product version."""
    if not ofuri and not product_stream_name:
        click.echo(ctx.get_help())
        exit(0)
    cond = {}
    if ofuri:
        cond["ofuri"] = ofuri
    if product_stream_name:
        # lookup ofuri
        q = core_queries.dep_us7_query()
        ofuri = q.execute(product_stream_name, None)["ofuri"]
        cond["ofuri"] = ofuri
    ctx.invoke(list_components, **cond)


@queries_grp.command(
    name="get-product-shipped-components",
    help="(DEP1US7) Get shipped-components",
)
@click.option("--ofuri", "ofuri", type=click.STRING, shell_complete=get_product_stream_ofuris)
@click.option(
    "--name", "product_stream_name", type=click.STRING, shell_complete=get_product_stream_names
)
@click.pass_context
def dep7_shipped_components_query(ctx, ofuri, product_stream_name):
    """List components of a specific product version."""
    if not ofuri and not product_stream_name:
        click.echo(ctx.get_help())
        exit(0)
    cond = {}
    if ofuri:
        cond["ofuri"] = ofuri
    if product_stream_name:
        # lookup ofuri
        q = core_queries.dep_us7_query()
        ofuri = q.execute(product_stream_name, None)["ofuri"]
        cond["ofuri"] = ofuri
    ctx.invoke(list_components, **cond)
