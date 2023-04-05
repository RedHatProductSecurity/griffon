"""

"""
import logging

import click
import click_completion

from griffon import (
    config_logging,
    get_config_option,
    list_config_sections,
    print_version,
)

from .commands.configure import configure_grp
from .commands.docs import docs_grp
from .commands.entities import entities_grp
from .commands.plugin_commands import plugin_commands
from .commands.queries import queries_grp
from .output import OUTPUT_FORMAT

logger = logging.getLogger("griffon")

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
    sources=(configure, entities, services_grp, docs, plugins),
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
@click.option(
    "--format",
    "-f",
    type=click.Choice([el.value for el in OUTPUT_FORMAT]),
    default=get_config_option("default", "format", "text"),
    help="Result format (default is text format).",
)
@click.option(
    "-v",
    "verbose",
    count=True,
    default=get_config_option("default", "verbosity", 0),
    help="Verbose output, more detailed search results, can be used multiple times (e.g. -vvv).",
)  # noqa
@click.option("--no-progress-bar", is_flag=True, help="Disable progress bar.")
@click.option("--no-color", is_flag=True, help="Disable output of color ansi esc sequences.")
@click.option(
    "--profile",
    "profile",
    type=click.Choice(list_config_sections()),
    default=get_config_option(
        "default",
        "profile",
    ),
    help="Activate profile, defined in .griffonrc.",
)
@click.option("--editor/--no-editor", default=True, help="Allow text editor prompt.")
@click.pass_context
def cli(ctx, debug, format, verbose, no_progress_bar, no_color, profile, editor):
    """Red Hat product security CLI"""

    if ctx.invoked_subcommand is None:
        click.echo(ctx.parent.get_help())

    if not debug:
        config_logging(level="INFO")
    else:
        config_logging(level="DEBUG")

    ctx.ensure_object(dict)
    ctx.obj["DEBUG"] = debug
    ctx.obj["SHOW_INACTIVE"] = False
    ctx.obj["SHOW_PURL"] = False
    ctx.obj["SHOW_UPSTREAM"] = False
    ctx.obj["FORMAT"] = format
    ctx.obj["VERBOSE"] = verbose
    ctx.obj["NO_PROGRESS_BAR"] = no_progress_bar
    ctx.obj["NO_COLOR"] = no_color
    ctx.obj["PROFILE"] = profile
    ctx.obj["SHORT_VERSION_VALUES"] = True
    ctx.obj["EDITOR"] = editor


cli.help = "Red Hat Product Security CLI"
