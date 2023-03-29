"""

"""
import logging

import click

from griffon import progress_bar
from griffon.autocomplete import (
    get_component_names,
    get_component_purls,
    get_product_stream_names,
    get_product_stream_ofuris,
)
from griffon.output import cprint
from griffon.services import ReportService, core_reports

logger = logging.getLogger("griffon")

report_service = ReportService()


@click.group(name="reports", help="Generate reports.")
@click.pass_context
def reports_grp(ctx):
    """Report operations."""
    pass


@reports_grp.command(name="report-affects", help="Generate Affects example report.")
@click.argument("product_version_name", required=False)
@click.option(
    "--show-components", is_flag=True, default=False, help="Show specific component counts."
)
@click.option("--all", is_flag=True, default=False, help="Show summary report on all affects.")
@click.option("--show-products", is_flag=True, default=False, help="Show specific product counts.")
@click.option("--purl", shell_complete=get_component_purls)
@click.option("--name", shell_complete=get_component_names)
@click.option("--product-name", shell_complete=get_product_stream_names)
@click.option("--ofuri", shell_complete=get_product_stream_ofuris)
@click.pass_context
@progress_bar
def generate_affects_report(
    ctx, product_version_name, all, show_components, show_products, purl, name, product_name, ofuri
):
    """A report operation"""
    if not all and not product_version_name:
        click.echo(ctx.get_help())
        exit(0)
    cprint(report_service.invoke(core_reports.example_affects_report, ctx.params), ctx=ctx)


@reports_grp.command(name="report-entities", help="Generate Entity report (with counts).")
@click.option("--all", is_flag=True, default=True, help="Show summary report on all entities.")
@click.pass_context
@progress_bar
def generate_entity_report(ctx, all):
    """A report operation"""
    if not all:
        click.echo(ctx.get_help())
        exit(0)
    cprint(report_service.invoke(core_reports.entity_report, ctx.params), ctx=ctx)


@reports_grp.command(name="report-license", help="Generate Product Stream license report.")
@click.argument(
    "product_stream_name",
    required=False,
    type=click.STRING,
    shell_complete=get_product_stream_names,
)
@click.option("--purl", help="Component Purl (must be quoted).")
@click.option(
    "--exclude_children", is_flag=True, default=False, help="Exclude children Component licenses."
)
@click.pass_context
@progress_bar
def generate_license_report(ctx, product_stream_name, purl, exclude_children):
    """A report operation"""
    if not product_stream_name and not purl:
        click.echo(ctx.get_help())
        exit(0)
    ctx.obj["FORMAT"] = "json"
    cprint(report_service.invoke(core_reports.license_report, ctx.params), ctx=ctx)
