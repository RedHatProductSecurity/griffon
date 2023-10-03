"""
minimal example of the Griffon plugin
"""

import click


@click.group(help="Example plugin")
@click.pass_context
def plugins(ctx):
    """Example plugin"""
    pass


@plugins.command()
def test():
    """Test command"""
    click.echo("Command 'test' of the 'example' plugin executed")


@plugins.command()
@click.option("-m", "--message", "message", help="Message to print out.")
def test_with_option(message):
    """Test with option command"""
    click.echo("Command 'test_with_option' of the 'example' plugin executed")
    click.echo(message)
