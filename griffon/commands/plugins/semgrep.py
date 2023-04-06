"""
semgrep plugin:

> griffon plugins semgrep setup

"""
import logging
import subprocess

import click

logger = logging.getLogger("griffon")


@click.group(help="semgrep plugin ")
@click.pass_context
def plugins(ctx):
    """semgrep plugin"""
    pass


try:
    # ensure semgrep is installed
    import semgrep  # noqa

    @plugins.command(help="Run this first, installs semgrep")
    @click.argument("scan_dir", required=False, type=click.Path(exists=True))
    @click.pass_context
    def scan(ctx, scan_dir):
        if not scan_dir:
            scan_dir = click.prompt("Please enter a valid directory path to scan")
        subprocess.run(["semgrep", "--config", "auto", scan_dir])

except Exception:
    pass


@plugins.command(help="Run this first, install semgrep python module")
@click.pass_context
def setup(ctx):
    subprocess.run(["pip", "install", "semgrep"])
