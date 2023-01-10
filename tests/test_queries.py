import inspect

from click.testing import CliRunner

from griffon.cli import cli
from griffon.service_layer import Query, core_queries


def test_queries():
    runner = CliRunner()
    result = runner.invoke(cli, ["queries"])
    assert result.exit_code == 0


def test_query_defs():
    for name, obj in inspect.getmembers(core_queries):
        if inspect.isclass(obj) and inspect.ismodule(obj):
            assert isinstance(obj, Query)
    assert isinstance(core_queries.cves_for_specific_component_query, Query)
    q: Query = core_queries.cves_for_specific_component_query()
    assert q
