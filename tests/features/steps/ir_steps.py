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
    "running > griffon --format {format} service {operation} {component} should find following latest components"  # noqa
)
def invoke_find_components(context, format, operation, component):
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
    if format == "json":
        out = json.loads(griffon_results.output)
        assert context.data[component] == out["count"]
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


@given(
    "running strict search > griffon --format {format} service {operation} -s {product_stream_name} should find following product"  # noqa
)
def invoke_find_products_with_strict_search(context, format, operation, product_stream_name):
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
            product_stream_name,
        ],
    )
    assert griffon_results.exit_code == 0
    output = cleanup_output(griffon_results.output)
    if format == "text":
        for row in context.table:
            assert row["product"] in output


@given(
    "running > griffon --format {format} service {operation} {product_stream_name} should find following products"  # noqa
)
def invoke_find_products(context, format, operation, product_stream_name):
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
            product_stream_name,
        ],
    )
    assert griffon_results.exit_code == 0
    output = cleanup_output(griffon_results.output)
    if format == "text":
        for row in context.table:
            assert row["product"] in output


@given(
    "running > griffon --format {format} service product-manifest {product_stream_name} should return manifest."  # noqa
)
def invoke_product_manifest(context, format, product_stream_name):
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
            "product-manifest",
            product_stream_name,
        ],
    )
    print(griffon_results.output)
    assert griffon_results.exit_code == 0

    if format == "json":
        output = json.loads(griffon_results.output)
        assert output["name"] == product_stream_name
    # if format == "text":
    #     for row in context.table:
    #         assert row["contain"] in output


@given(
    "running > griffon --format {format} service component-flaws {component_name} should return list of flaws."  # noqa
)
def invoke_component_flaws(context, format, component_name):
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
            "component-flaws",
            component_name,
        ],
    )
    print(griffon_results.output)
    assert griffon_results.exit_code == 0

    # if format == "json":
    #     output = json.loads(griffon_results.output)
    #     assert output["name"] == product_stream_name
    # if format == "text":
    #     for row in context.table:
    #         assert row["contain"] in output


@given(
    "running > griffon --format {format} service product-flaws {product_version_name} should return list of flaws."  # noqa
)
def invoke_product_flaws(context, format, product_version_name):
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
            "product-flaws",
            product_version_name,
        ],
    )
    print(griffon_results.output)
    assert griffon_results.exit_code == 0

    # if format == "json":
    #     output = json.loads(griffon_results.output)
    #     assert output["name"] == product_stream_name
    # if format == "text":
    #     for row in context.table:
    #         assert row["contain"] in output
