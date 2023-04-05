import pytest
from click.testing import CliRunner

from griffon.cli import cli

pytestmark = pytest.mark.unit


def test_osidb():
    runner = CliRunner()
    result = runner.invoke(cli, ["entities", "OSIDB", "admin"])
    assert result.exit_code == 0


def test_corgi():
    runner = CliRunner()
    result = runner.invoke(cli, ["entities", "CORGI", "admin"])
    assert result.exit_code == 0
