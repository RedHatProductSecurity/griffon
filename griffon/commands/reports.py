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

logger = logging.getLogger("rich")

report_service = ReportService()


@click.group(name="reports", help="Generate reports.")
@click.pass_context
def reports_grp(ctx):
    """Report operations."""
    pass


@reports_grp.command(name="report-affects", help="Generate Affects example report.")
@click.option(
    "--show-components", is_flag=True, default=False, help="Show specific component counts."
)
@click.option("--show-products", is_flag=True, default=False, help="Show specific product counts.")
@click.option("--purl", shell_complete=get_component_purls)
@click.option("--name", shell_complete=get_component_names)
@click.option("--product-name", shell_complete=get_product_stream_names)
@click.option("--ofuri", shell_complete=get_product_stream_ofuris)
@click.pass_context
@progress_bar
def generate_affects_report(ctx, show_components, show_products, purl, name, product_name, ofuri):
    """A report operation"""
    cprint(report_service.invoke(core_reports.example_affects_report, ctx.params), ctx=ctx)
