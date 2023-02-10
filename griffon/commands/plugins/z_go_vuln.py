"""
vuln.go.dev plugin:


"""
import click
import requests

from griffon.output import cprint

api_url = "https://vuln.go.dev"


@click.group()
@click.pass_context
def plugins(ctx):
    """vuln.go.dev plugin"""
    pass


@plugins.command()
@click.option("--id", "go_id", help="go vuln ID (ex. GO-2022-0189")
@click.option("--cve-id", "cve_id", help="retrieve by CVE_ID alias")
@click.pass_context
def get(ctx, go_id, cve_id):
    """Search go.vuln.dev by go vuln ID"""
    if not go_id and not cve_id:
        click.echo(ctx.get_help())
        exit(0)

    if cve_id:
        res = requests.get(f"https://pkg.go.dev/search?q={cve_id}")
        go_id = res.url.split("/")[-1]
    if go_id:
        res = requests.get(f"{api_url}/ID/{go_id}.json")
        cprint(res.json(), ctx=ctx)


@plugins.command()
@click.option(
    "-q",
    "search_term",
)
@click.pass_context
def search(ctx, search_term):
    """Search go.vuln.dev"""
    if not search_term:
        click.echo(ctx.get_help())
        exit(0)
    click.launch(f"https://pkg.go.dev/search?q={search_term}")
