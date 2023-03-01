"""

"""
import logging

import click
import click_completion

from griffon import get_config, print_version

from .commands.configure import configure_grp
from .commands.docs import docs_grp
from .commands.entities import entities_grp
from .commands.manage import manage_grp
from .commands.plugin_commands import plugin_commands
from .commands.queries import queries_grp
from .output import OUTPUT_FORMAT

logger = logging.getLogger("griffon")

click_completion.init()

griffon_config = get_config()


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


services_grp.add_command(queries_grp)


@click.group()
@click.pass_context
def docs(ctx):
    pass


docs.add_command(docs_grp)


@click.group()
@click.pass_context
def plugins(ctx):
    pass


@plugins.command(name="plugins", help="3rd party plugins.", cls=plugin_commands)
@click.pass_context
def plugins_grp(ctx):
    pass


# CLI entry point
#
#   A click.CommandCollection is used to aggregate up all CLI sub commands.
#   Top level CLI options (germane to all commands) are included here.


@click.group(
    cls=click.CommandCollection,
    sources=(configure, entities, services_grp, manage, docs, plugins),
)
@click.option(
    "--version",
    "-V",
    is_flag=True,
    callback=print_version,
    expose_value=False,
    is_eager=True,
    help="Display griffon version.",
)
@click.option("--debug", "-d", is_flag=True, help="Debug log level.")
# @click.option("--show-inactive", is_flag=True, default=False, help="Show inactive Products.")
# @click.option("--show-purl", is_flag=True, help="Display full purl.")
# @click.option("--show-upstream", is_flag=True, default=False, help="Show UPSTREAM components.")
@click.option(
    "--format",
    "-f",
    type=click.Choice([el.value for el in OUTPUT_FORMAT]),
    default=griffon_config["default"]["format"],
    help="Result format (default is text).",
)
@click.option(
    "-v",
    "verbose",
    count=True,
    help="Verbose output, more detailed search results, can be used multiple times (e.g. -vvv).",
)  # noqa
@click.option("--no-progress-bar", is_flag=True, help="Disable progress bar.")
@click.option("--no-color", is_flag=True, help="Disable output of color ansi esc sequences.")
@click.pass_context
def cli(ctx, debug, format, verbose, no_progress_bar, no_color):
    """Red Hat product security CLI"""

    if ctx.invoked_subcommand is None:
        click.echo(ctx.parent.get_help())

    if debug:
        logger.setLevel("DEBUG")

    ctx.ensure_object(dict)
    ctx.obj["DEBUG"] = debug
    ctx.obj["SHOW_INACTIVE"] = False
    ctx.obj["SHOW_PURL"] = False
    ctx.obj["SHOW_UPSTREAM"] = False
    ctx.obj["FORMAT"] = format
    ctx.obj["VERBOSE"] = verbose
    ctx.obj["NO_PROGRESS_BAR"] = no_progress_bar
    ctx.obj["NO_COLOR"] = no_color


cli.help = "Red Hat Product Security CLI"
