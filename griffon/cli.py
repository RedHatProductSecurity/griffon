"""

"""
import logging

import click
import click_completion

from griffon import get_logging

from .commands.configure import configure_grp
from .commands.docs import docs_grp
from .commands.entities import entities_grp
from .commands.manage import manage_grp
from .commands.plugin_commands import plugin_commands
from .commands.process import process_grp
from .commands.queries import queries_grp
from .commands.reports import reports_grp
from .output import OUTPUT_FORMAT

logger = logging.getLogger("rich")

click_completion.init()


@click.group()
@click.pass_context
def configure(ctx):
    pass


configure.add_command(configure_grp)


@click.group()
@click.pass_context
def entities(ctx):
    pass


entities.add_command(entities_grp)


@click.group()
@click.pass_context
def manage(ctx):
    pass


manage.add_command(manage_grp)


@click.group()
@click.pass_context
def services_grp(ctx):
    pass


@services_grp.group(name="service", help="Service operations.")
@click.pass_context
def services(ctx):
    pass


services.add_command(queries_grp)
services.add_command(process_grp)
services.add_command(reports_grp)


@click.group()
@click.pass_context
def docs(ctx):
    pass


docs.add_command(docs_grp)


# CLI entry point
#
#   A click.CommandCollection is used to aggregate up all CLI sub commands.
#   Top level CLI options (germane to all commands) are included here.


@click.group(
    cls=click.CommandCollection,
    sources=(configure, entities, services_grp, manage, docs, plugin_commands),
)
@click.option("--debug", is_flag=True)
@click.option(
    "--format",
    type=click.Choice([el.value for el in OUTPUT_FORMAT]),
    default="json",
)
@click.pass_context
def cli(ctx, debug, format):
    """Red Hat product security CLI"""

    if ctx.invoked_subcommand is None:
        click.echo(ctx.parent.get_help())

    if debug:
        get_logging(level="DEBUG")

    ctx.ensure_object(dict)
    ctx.obj["DEBUG"] = debug
    ctx.obj["FORMAT"] = format


cli.help = "Red Hat Product Security CLI"
