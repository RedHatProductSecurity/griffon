from click.testing import CliRunner

from griffon.cli import cli


def test_osv():
    runner = CliRunner()
    result = runner.invoke(cli, ["z_osv"])
    assert result.exit_code == 0


def test_fcc():
    runner = CliRunner()
    result = runner.invoke(cli, ["z_fcc"])
    assert result.exit_code == 0
