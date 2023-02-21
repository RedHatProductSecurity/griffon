import inspect

import pytest
from click.testing import CliRunner

from griffon.cli import cli
from griffon.services import Process, core_process


@pytest.mark.unit
def test_processes():
    runner = CliRunner()
    result = runner.invoke(cli, ["service"])
    assert result.exit_code == 0


@pytest.mark.integration
def test_process_defs():
    for name, obj in inspect.getmembers(core_process):
        if inspect.isclass(obj) and inspect.ismodule(obj):
            assert isinstance(obj, Process)
    assert isinstance(core_process.generate_affects_for_specific_component_process, Process)
    q: Process = core_process.generate_affects_for_specific_component_process()
    assert q
