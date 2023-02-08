import pytest
from click.testing import CliRunner

from griffon.cli import cli

pytestmark = pytest.mark.unit

# @pytest.skip
# def test_cli_verbose():
#     runner = CliRunner()
#     result = runner.invoke(cli, ["-v"])
#     assert result.exit_code == 0, result.output
#
#
# @pytest.skip
# def test_cli_version():
#     runner = CliRunner()
#     result = runner.invoke(cli, ["-V"])
#     assert result.exit_code == 0
#     assert result.output == "griffon 0.1.0\n"
#


def test_cli_components():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
