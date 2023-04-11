import pytest
from click.testing import CliRunner

from griffon.cli import cli

pytestmark = pytest.mark.unit


def test_osidb():
    runner = CliRunner()
    result = runner.invoke(cli, ["entities", "osidb", "admin"])
    assert result.exit_code == 0


def test_corgi():
    runner = CliRunner()
    result = runner.invoke(cli, ["entities", "component-registry", "admin"])
    assert result.exit_code == 0


def test_community_components():
    runner = CliRunner()
    result = runner.invoke(cli, ["entities", "community-component-registry", "admin"])
    assert result.exit_code == 0
