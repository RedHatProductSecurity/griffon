import pytest
from click.testing import CliRunner

from griffon.cli import cli

pytestmark = pytest.mark.unit


def test_cli_flaws():
    runner = CliRunner()
    result = runner.invoke(cli, ["entities", "flaws"])
    assert result.exit_code == 0


def test_cli_components():
    runner = CliRunner()
    result = runner.invoke(cli, ["entities", "components"])
    assert result.exit_code == 0
