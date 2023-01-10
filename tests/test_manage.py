from click.testing import CliRunner

from griffon.cli import cli


def test_osidb():
    runner = CliRunner()
    result = runner.invoke(cli, ["manage", "osidb"])
    assert result.exit_code == 0


def test_corgi():
    runner = CliRunner()
    result = runner.invoke(cli, ["manage", "corgi"])
    assert result.exit_code == 0
