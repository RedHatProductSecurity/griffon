import logging

import click

from .corgi import corgi_grp
from .osidb import osidb_grp

logger = logging.getLogger("griffon")


default_conditions: dict = {}


@click.group(name="entities", help="Entity operations.")
@click.option("--open-browser", is_flag=True, help="open browser to service results.")
@click.option("--limit", default=10, help="# of items returned by list operations.")
@click.pass_context
def entities_grp(ctx, open_browser, limit):
    ctx.ensure_object(dict)
    ctx.obj["open_browser"] = open_browser
    ctx.obj["limit"] = limit


entities_grp.add_command(osidb_grp)
entities_grp.add_command(corgi_grp)
