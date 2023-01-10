"""
vuln.go.dev plugin:


"""
import click

api_url = "https://vuln.go.dev/ID"


@click.group()
@click.pass_context
def plugins(ctx):
    """vuln.go.dev plugin"""
    pass


@plugins.command()
@click.option("--id", "go_id", help="go vuln ID (ex. GO-2022-0189")
@click.pass_context
def get(ctx, go_id):
    """Search go.vuln.dev by go vuln ID"""
    if not go_id:
        click.echo(ctx.get_help())
        exit(0)
    click.launch(f"{api_url}/{go_id}.json")
