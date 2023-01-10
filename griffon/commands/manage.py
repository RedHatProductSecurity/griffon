"""

"""
import logging

import click

from griffon import CORGI_API_URL, OSIDB_API_URL, CorgiService, OSIDBService
from griffon.output import cprint

logger = logging.getLogger("rich")


@click.group(name="manage")
@click.pass_context
def manage_grp(ctx):
    """Manage operations."""
    pass


# griffon manage commands
@manage_grp.group()
@click.pass_context
def griffon(ctx):
    """Manage griffon"""
    pass


@griffon.command(name="refresh")
def refresh_autocompletion():
    """retrieve project stream names for autocompletion"""
    pass


# osidb manage commands
@manage_grp.group()
@click.pass_context
def osidb(ctx):
    """Manage osidb"""
    pass


@osidb.command(name="status")
def osidb_status():
    session = OSIDBService.create_session()
    data = session.status()
    return cprint(data)


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
def corgi_status():
    session = CorgiService.create_session()
    data = session.status()
    return cprint(data.additional_properties)


@corgi.command(name="data")
def corgi_data():
    click.launch(f"{CORGI_API_URL}/data")


@corgi.command(name="api_doc")
def corgi_api_docs():
    click.launch(f"{CORGI_API_URL}/api/v1/schema/docs")
