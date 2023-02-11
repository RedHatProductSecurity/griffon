"""

"""
import logging

import click

from griffon import progress_bar
from griffon.output import cprint
from griffon.services import core_reports

logger = logging.getLogger("rich")


# ------------------------------------------------------------------------- Reports


@click.group(name="reports", help="Generate reports.")
@click.pass_context
def reports_grp(ctx):
    """Report operations."""
    pass


@reports_grp.command(name="affects", help="Generate Affects example report.")
@click.option(
    "--show-components", is_flag=True, default=False, help="Show specific component counts."
)
@click.option("--show-products", is_flag=True, default=False, help="Show specific product counts.")
@click.pass_context
@progress_bar
def generate_affects_report(ctx, show_components, show_products):
    """A report operation"""
    q = core_reports.example_affects_report()
    cprint(q.execute({"show_components": show_components, "show_products": show_products}), ctx=ctx)
