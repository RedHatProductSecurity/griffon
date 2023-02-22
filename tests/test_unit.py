import click
import pytest

from griffon.commands.queries import product_versions_affected_by_cve_query
from griffon.output import OUTPUT_FORMAT, cprint

pytestmark = pytest.mark.unit


def test_output_formats():

    assert OUTPUT_FORMAT("json") == OUTPUT_FORMAT.JSON
    assert OUTPUT_FORMAT.TEXT.value == "text"

    single_result_data = {
        "ofuri": "o:redhat:ansible_automation_platform:2.2",
        "name": "ansible_automation_platform-2.2",
        "product": "ansible-automation-platform",
        "product_version": "ansible_automation_platform-2",
        "brew_tags": [
            "ansible-automation-platform-2.2-rhel-8",
            "ansible-automation-platform-2.2-rhel-9",
            "ansible-automation-platform-2.2-rhel-8-container-released",
            "ansible-automation-platform-2.2-rhel-9-container-released",
        ],
        "build_count": 1033,
        "latest_component_count": 246,
    }
    with pytest.raises(SystemExit) as capture_err:
        ctx = click.Context(
            product_versions_affected_by_cve_query,
            obj={
                "NO_COLOR": False,
                "NO_PROGRESS_BAR": False,
                "SHOW_INACTIVE": False,
                "SHOW_UPSTREAM": False,
            },
        )
        assert cprint(single_result_data, ctx=ctx)
    assert capture_err
    assert capture_err.type == SystemExit
    assert capture_err.value.code == 0
