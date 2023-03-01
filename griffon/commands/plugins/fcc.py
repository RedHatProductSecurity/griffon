"""
FCC plugin:


"""
import click

api_url = "https://fcc.io"


@click.group()
@click.pass_context
def plugins(ctx):
    """FCC plugin"""
    pass


@plugins.command()
@click.option("--fcc-id", help="FCC ID")
@click.pass_context
def search(ctx, fcc_id):
    """Search FCC by FCC ID"""
    if not fcc_id:
        click.echo(ctx.get_help())
        exit(0)
    click.launch(f"{api_url}/{fcc_id}")
