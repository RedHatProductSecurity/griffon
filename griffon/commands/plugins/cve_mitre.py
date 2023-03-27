"""
FCC plugin:


"""
import click

api_url = "https://cve.mitre.org"


@click.group()
@click.pass_context
def plugins(ctx):
    """mitre cve plugin"""
    pass


@plugins.command()
@click.argument(
    "cve_id",
    required=True,
    type=click.STRING,
)
@click.pass_context
def search(ctx, cve_id):
    """Search cve mitre by CVE ID"""
    if not cve_id:
        click.echo(ctx.get_help())
        exit(0)
    click.launch(f"{api_url}/cgi-bin/cvename.cgi?name={cve_id}")
