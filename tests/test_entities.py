import pytest
from click.testing import CliRunner

from griffon.cli import cli

pytestmark = pytest.mark.unit


def test_cli_flaws():
    runner = CliRunner()
    result = runner.invoke(cli, ["entities", "osidb", "flaws"])
    assert result.exit_code == 0


def test_cli_affects():
    runner = CliRunner()
    result = runner.invoke(cli, ["entities", "osidb", "affects"])
    assert result.exit_code == 0


def test_cli_trackers():
    runner = CliRunner()
    result = runner.invoke(cli, ["entities", "osidb", "trackers"])
    assert result.exit_code == 0


def test_cli_components():
    runner = CliRunner()
    result = runner.invoke(cli, ["entities", "component-registry", "components"])
    assert result.exit_code == 0


def test_cli_builds():
    runner = CliRunner()
    result = runner.invoke(cli, ["entities", "component-registry", "builds"])
    assert result.exit_code == 0


def test_cli_product_streams():
    runner = CliRunner()
    result = runner.invoke(cli, ["entities", "component-registry", "product-streams"])
    assert result.exit_code == 0


def test_cli_community_components():
    runner = CliRunner()
    result = runner.invoke(cli, ["entities", "community-component-registry", "components"])
    assert result.exit_code == 0


def test_cli_community_builds():
    runner = CliRunner()
    result = runner.invoke(cli, ["entities", "community-component-registry", "builds"])
    assert result.exit_code == 0


def test_cli_community_product_streams():
    runner = CliRunner()
    result = runner.invoke(cli, ["entities", "community-component-registry", "product-streams"])
    assert result.exit_code == 0
