"""
osv plugin:

https://osv.dev/docs/#tag/api/operation/OSV_QueryAffected

"""
import json
import logging

import click
import requests

from griffon.output import cprint

logger = logging.getLogger("griffon")

api_url = "https://api.osv.dev/v1/query"


@click.group()
@click.pass_context
def plugins(ctx):
    """OSV plugin"""
    pass


@plugins.command()
@click.option("--version", "package_version", help="package version")
@click.option("--name", "package_name", help="package name")
@click.option("--ecosystem", help="ecosystem (ex. PyPI) ")
@click.pass_context
def query_by_version(ctx, package_version, package_name, ecosystem):
    if not package_version and not package_name:
        click.echo(ctx.get_help())
        exit(0)
    data = json.dumps(
        {"version": package_version, "package": {"name": package_name, "ecosystem": ecosystem}}
    )
    res = requests.post(
        api_url,
        data=data,
        headers={"Content-type": "application/json"},
    )
    cprint(res.json(), ctx=ctx)


@plugins.command()
@click.option("--commit_hash", help="specific commit hash")
@click.pass_context
def query_by_commit_hash(ctx, commit_hash):
    if not commit_hash:
        click.echo(ctx.get_help())
        exit(0)
    data = json.dumps({"commit": commit_hash})
    res = requests.post(
        api_url,
        data=data,
        headers={"Content-type": "application/json"},
    )
    cprint(res.json(), ctx=ctx)
