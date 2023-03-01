"""

"""
import logging

import click

from griffon import CORGI_API_URL, OSIDB_API_URL, CorgiService, OSIDBService
from griffon.output import console, cprint

logger = logging.getLogger("griffon")


@click.group(name="manage")
@click.pass_context
def manage_grp(ctx):
    """Manage operations."""
    pass


# osidb manage commands
@manage_grp.group()
@click.pass_context
def osidb(ctx):
    """Manage osidb"""
    pass


@osidb.command(name="status")
@click.pass_context
def osidb_status(ctx):
    session = OSIDBService.create_session()
    data = session.status()
    return cprint(data, ctx=ctx)


@osidb.command(name="api_doc")
def osidb_api_docs():
    click.launch(f"{OSIDB_API_URL}/osidb/api/v1/schema/swagger-ui/")


# component-registry manage commands
@manage_grp.group()
@click.pass_context
def corgi(ctx):
    """Manage component registry"""
    pass


@corgi.command(name="status")
@click.pass_context
def corgi_status(ctx):
    session = CorgiService.create_session()
    data = session.status()
    return cprint(data.additional_properties, ctx=ctx)


@corgi.command(name="health")
@click.pass_context
def corgi_health(ctx):
    try:
        session = CorgiService.create_session()
        status = session.status()["status"]
        if status == "ok":
            console.log(f"{CORGI_API_URL} is operational")
        else:
            console.log(f"{CORGI_API_URL} is NOT operational")
            exit(1)
    except:  # noqa
        console.log(f"{CORGI_API_URL} is NOT operational")
        raise click.ClickException("Component registry health check failed.")


@corgi.command(name="data")
def corgi_data():
    click.launch(f"{CORGI_API_URL}/data")


@corgi.command(name="api_doc")
def corgi_api_docs():
    click.launch(f"{CORGI_API_URL}/api/v1/schema/docs")
