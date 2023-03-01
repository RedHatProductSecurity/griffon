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
