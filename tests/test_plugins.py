import pytest
from click.testing import CliRunner

from griffon.cli import cli

pytestmark = pytest.mark.unit


def test_osv():
    runner = CliRunner()
    result = runner.invoke(cli, ["plugins", "osv"])
    assert result.exit_code == 0


def test_fcc():
    runner = CliRunner()
    result = runner.invoke(cli, ["plugins", "fcc"])
    assert result.exit_code == 0


def test_semgrep():
    runner = CliRunner()
    result = runner.invoke(cli, ["plugins", "semgrep"])
    assert result.exit_code == 0


def test_go_vuln():
    runner = CliRunner()
    result = runner.invoke(cli, ["plugins", "go_vuln"])
    assert result.exit_code == 0


def test_cve_mitre():
    runner = CliRunner()
    result = runner.invoke(cli, ["plugins", "cve_mitre"])
    assert result.exit_code == 0


def test_cvelib():
    runner = CliRunner()
    result = runner.invoke(cli, ["plugins", "cvelib"])
    assert result.exit_code == 0
