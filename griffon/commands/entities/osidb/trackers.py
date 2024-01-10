"""
osidb tracker entities operations
"""

import logging

import click
from osidb_bindings.bindings.python_client.api.osidb import (
    osidb_api_v1_trackers_list,
    osidb_api_v1_trackers_retrieve,
)
from osidb_bindings.bindings.python_client.models import Tracker

from griffon import OSIDB_SERVER_URL, OSIDBService, progress_bar
from griffon.commands.entities.helpers import (
    multivalue_params_to_csv,
    query_params_options,
)
from griffon.output import cprint

logger = logging.getLogger("griffon")


@click.group(help=f"{OSIDB_SERVER_URL}/osidb/api/v1/trackers")
@click.pass_context
def trackers(ctx):
    """OSIDB Trackers."""
    pass


@trackers.command(name="list")
@query_params_options(
    entity="Tracker",
    endpoint_module=osidb_api_v1_trackers_list,
    options_overrides={
        "include_fields": {"type": click.Choice(OSIDBService.get_fields(Tracker))},
        "exclude_fields": {"type": click.Choice(OSIDBService.get_fields(Tracker))},
        "include_meta_attr": {"type": click.Choice(OSIDBService.get_meta_attr_fields(Tracker))},
    },
)
@click.pass_context
def list_trackers(ctx, **params):
    # TODO: handle pagination
    # TODO: handle output
    session = OSIDBService.create_session()

    params = multivalue_params_to_csv(params)
    return cprint(
        list(session.trackers.retrieve_list_iterator_async(max_results=5000, **params)), ctx=ctx
    )


@trackers.command(name="get")
@click.option("--uuid", "tracker_uuid", help="Tracker UUID.", required=True)
@query_params_options(
    entity="Tracker",
    endpoint_module=osidb_api_v1_trackers_retrieve,
    options_overrides={
        "include_fields": {"type": click.Choice(OSIDBService.get_fields(Tracker))},
        "exclude_fields": {"type": click.Choice(OSIDBService.get_fields(Tracker))},
        "include_meta_attr": {"type": click.Choice(OSIDBService.get_meta_attr_fields(Tracker))},
    },
)
@click.pass_context
@progress_bar()
def get_tracker(ctx, tracker_uuid, **params):
    params = multivalue_params_to_csv(params)

    session = OSIDBService.create_session()
    data = session.trackers.retrieve(tracker_uuid, **params)
    return cprint(data, ctx=ctx)
