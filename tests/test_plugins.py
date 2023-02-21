import pytest
from click.testing import CliRunner

from griffon.cli import cli

pytestmark = pytest.mark.unit


def test_osv():
    runner = CliRunner()
    result = runner.invoke(cli, ["plugins", "z_osv"])
    assert result.exit_code == 0


def test_fcc():
    runner = CliRunner()
    result = runner.invoke(cli, ["plugins", "z_fcc"])
    assert result.exit_code == 0
