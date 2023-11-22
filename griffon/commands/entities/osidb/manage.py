"""
osidb manage operations

"""
import logging

import click

from griffon import OSIDB_SERVER_URL, OSIDBService
from griffon.output import cprint

logger = logging.getLogger("griffon")

default_conditions: dict = {}


@click.group(name="admin")
@click.pass_context
def manage_grp(ctx):
    """Manage osidb"""
    pass


@manage_grp.command(name="status")
@click.pass_context
def osidb_status(ctx):
    session = OSIDBService.create_session()
    data = session.status()
    return cprint(data, ctx=ctx)


@manage_grp.command(name="api_doc")
def osidb_api_docs():
    click.launch(f"{OSIDB_SERVER_URL}/osidb/api/v1/schema/swagger-ui/")
