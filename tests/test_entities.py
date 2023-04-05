import pytest
from click.testing import CliRunner

from griffon.cli import cli

pytestmark = pytest.mark.unit


def test_cli_flaws():
    runner = CliRunner()
    result = runner.invoke(cli, ["entities", "OSIDB", "flaws"])
    assert result.exit_code == 0


def test_cli_affects():
    runner = CliRunner()
    result = runner.invoke(cli, ["entities", "OSIDB", "affects"])
    assert result.exit_code == 0


def test_cli_trackers():
    runner = CliRunner()
    result = runner.invoke(cli, ["entities", "OSIDB", "trackers"])
    assert result.exit_code == 0


def test_cli_components():
    runner = CliRunner()
    result = runner.invoke(cli, ["entities", "CORGI", "components"])
    assert result.exit_code == 0


def test_cli_builds():
    runner = CliRunner()
    result = runner.invoke(cli, ["entities", "CORGI", "builds"])
    assert result.exit_code == 0


def test_cli_product_streams():
    runner = CliRunner()
    result = runner.invoke(cli, ["entities", "CORGI", "product-streams"])
    assert result.exit_code == 0
