import inspect

import pytest
from click.testing import CliRunner

from griffon.cli import cli
from griffon.services import Query, core_reports


@pytest.mark.unit
def test_reports():
    runner = CliRunner()
    result = runner.invoke(cli, ["service"])
    assert result.exit_code == 0


@pytest.mark.integration
def test_query_defs():
    for name, obj in inspect.getmembers(core_reports):
        if inspect.isclass(obj) and inspect.ismodule(obj):
            assert isinstance(obj, Query)
    assert isinstance(core_reports.example_affects_report, Query)
    q: Query = core_reports.example_affects_report()
    assert q
