import json
import re

from behave import given, then
from click.testing import CliRunner

from griffon.cli import cli


def cleanup_output(data):
    """strip output of ansi esc sequences (eg. color codes)"""
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", data)


@given("a set of product_streams")
def step_impl(context):
    data = getattr(context, "data", None)
    if not data:
        context.data = {}
    for row in context.table:
        context.data[row["product_stream"]] = int(row["count"])


@then(
    "running > griffon --format {format} service {operation} --name {product_stream} should find following latest components"  # noqa
)
def invoke_find_components(context, format, operation, product_stream):
    runner = CliRunner()
    # griffon invoked with --no-color to disable emitting ansi escape
    # sequences and --no-progress-bar to disable omitting extraneous text
    # to stdout
    griffon_results = runner.invoke(
        cli,
        [
            "--no-progress-bar",
            "--no-color",
            "--format",
            format,
            "service",
            operation,
            "--name",
            product_stream,
        ],
    )
    assert griffon_results.exit_code == 0
    if format == "json":
        out = json.loads(griffon_results.output)
        print(out)
        assert context.data[product_stream] == out["count"]
        for row in context.table:
            assert [item for item in out["results"] if item.get("purl") == row["component"]]

    if format == "text":
        output = cleanup_output(griffon_results.output)
        for row in context.table:
            assert row["component"] in output


@then(
    "running > griffon --format {format} service {operation} {component} should find following product_versions"  # noqa
)
def invoke_find_product_streams(context, format, operation, component):
    runner = CliRunner()
    # griffon invoked with --no-color to disable emitting ansi escape
    # sequences and --no-progress-bar to disable omitting extraneous text
    # to stdout
    griffon_results = runner.invoke(
        cli,
        [
            "--no-progress-bar",
            "--no-color",
            "--format",
            format,
            "service",
            operation,
            component,
        ],
    )
    assert griffon_results.exit_code == 0
    output = cleanup_output(griffon_results.output)
    if format == "text":
        for row in context.table:
            assert row["output"] in output


@then(
    "running strict search > griffon --format {format} service {operation} -s {component} should find following product_versions"  # noqa
)
def invoke_find_product_streams_strict(context, format, operation, component):
    runner = CliRunner()
    # griffon invoked with --no-color to disable emitting ansi escape
    # sequences and --no-progress-bar to disable omitting extraneous text
    # to stdout
    griffon_results = runner.invoke(
        cli,
        [
            "--no-progress-bar",
            "--no-color",
            "--format",
            format,
            "service",
            operation,
            "-s",
            component,
        ],
    )
    assert griffon_results.exit_code == 0
    output = cleanup_output(griffon_results.output)
    if format == "text":
        for row in context.table:
            assert row["output"] in output
