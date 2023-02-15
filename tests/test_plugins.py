import pytest
from click.testing import CliRunner

from griffon.cli import cli

pytestmark = pytest.mark.unit


def test_osv():
    runner = CliRunner()
    result = runner.invoke(cli, ["z_osv"])
    assert result.exit_code == 0


def test_fcc():
    runner = CliRunner()
    result = runner.invoke(cli, ["z_fcc"])
    assert result.exit_code == 0


def test_go_vuln():
    runner = CliRunner()
    result = runner.invoke(cli, ["z_go_vuln"])
    assert result.exit_code == 0
