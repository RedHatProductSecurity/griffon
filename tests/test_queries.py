import inspect

import pytest
from click.testing import CliRunner

from griffon.cli import cli
from griffon.services import Query, core_queries


@pytest.mark.unit
def test_queries():
    runner = CliRunner()
    result = runner.invoke(cli, ["service"])
    assert result.exit_code == 0


@pytest.mark.integration
def test_query_defs():
    for name, obj in inspect.getmembers(core_queries):
        if inspect.isclass(obj) and inspect.ismodule(obj):
            assert isinstance(obj, Query)
    assert isinstance(core_queries.product_stream_summary, Query)
    q: Query = core_queries.product_stream_summary()
    assert q
