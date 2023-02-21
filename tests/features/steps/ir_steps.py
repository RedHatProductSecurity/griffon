import json

from behave import given, then
from click.testing import CliRunner

from griffon.cli import cli


@given("a set of product_streams")
def step_impl(context):
    data = getattr(context, "data", None)
    if not data:
        context.data = {}
    for row in context.table:
        context.data[row["product_stream"]] = int(row["count"])


@then(
    "running > griffon --format {format} service queries {operation} --name {product_stream} should find following latest components"  # noqa
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
        print(griffon_results.output)
        for row in context.table:
            assert row["component"] in griffon_results.output


@then(
    "running > griffon --format {format} service queries {operation} --name {component} should find following product_streams"  # noqa
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
            "--name",
            component,
        ],
    )
    assert griffon_results.exit_code == 0
    if format == "json":
        out = json.loads(griffon_results.output)
        print(out)
        for row in context.table:
            assert [item for item in out["results"] if item.get("name") == row["product_stream"]]
    if format == "text":
        print(griffon_results.output)
        for row in context.table:
            assert row["product_stream"] in griffon_results.output
