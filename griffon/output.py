import enum
import json
import logging

import click
from rich import inspect
from rich.console import Console
from rich.table import Table
from rich.text import Text

console = Console()

logger = logging.getLogger("rich")


class OUTPUT_FORMAT(enum.Enum):
    JSON = "json"
    TEXT = "text"
    TABLE = "table"
    DEBUG = "debug"


class DEST(enum.Enum):
    CONSOLE = "console"
    FILE = "file"


def raw_json_transform(data, show_count: bool) -> dict:
    """normalise all data to dict"""
    if type(data) is list:
        results = []
        for d in data:
            if type(d) is dict:
                results.append(d)
            else:
                results.append(d.to_dict())
        output = {
            "results": results,
        }
        if show_count:
            output["count"] = len(results)  # type: ignore
    else:
        if type(data) is dict:
            output = data
        else:
            output = data.to_dict()
    return output


def entity_type(data):
    entity_type = "unknown"
    if "cve_id" in data:
        entity_type = "flaw"
    if "purl" in data:
        entity_type = "component"
    if "affectedness" in data:
        entity_type = "affect"
    if "ofuri" in data:
        entity_type = "product"
    return entity_type


def cprint(
    data,
    dest=DEST.CONSOLE,
    filename=None,
    ctx=None,
    show_count: bool = True,
):
    """handle format and output"""
    output = raw_json_transform(data, show_count)
    format = OUTPUT_FORMAT.JSON
    if ctx and "FORMAT" in ctx.obj:
        format = OUTPUT_FORMAT(ctx.obj["FORMAT"])

    if format is OUTPUT_FORMAT.DEBUG:
        inspect(output)

    if format is OUTPUT_FORMAT.TEXT:
        # TODO - we may want something a bit more full featured for templating ... opting for
        #    simple for now.
        if ctx.info_name == "components-contain-component":
            if "results" in output:
                for item in output["results"]:
                    console.print("link:", item["link"])
                    console.print("name:", item["name"])
                    console.print("purl:", item["purl"])
                    console.print(
                        "sources:",
                    )
                    ordered_sources = sorted(item["sources"], key=lambda d: d["purl"])
                    for source in ordered_sources:
                        console.print(source["purl"])
            else:
                console.print("link:", output["link"])
                console.print("name:", output["name"])
                console.print("purl:", output["purl"])
                console.print(
                    "sources:",
                )
                ordered_sources = sorted(output["sources"], key=lambda d: d["purl"])
                for source in ordered_sources:
                    console.print(source["purl"])
            ctx.exit(0)

        if ctx.info_name == "product-contain-component":
            component_purl = ctx.params["purl"]
            if "results" in output and output["count"] > 0:
                ordered_results = sorted(output["results"], key=lambda d: d["name"])
                for row in ordered_results:
                    product_name = Text(row["name"])
                    product_name.stylize("bold magenta")
                    if "component_purl" in row:
                        component_purl = row["component_purl"]
                    console.print(product_name, " ", component_purl, no_wrap=True)
            ctx.exit(0)

        if ctx.info_name == "product-summary":
            for k, v in output.items():
                key_name = Text(k)
                key_name.stylize("bold magenta")
                console.print(key_name, " : ", v, no_wrap=True)
            ctx.exit(0)

        if ctx.info_name == "components-affected-by-cve":
            console.print("link:", output["link"])
            console.print("cve_id:", output["cve_id"])
            console.print("title:", output["title"])
            console.print(
                "affects:",
            )
            ordered_affects = sorted(output["affects"], key=lambda d: d["product_version_name"])
            for affect in ordered_affects:
                for component in affect["components"]:
                    console.print(
                        affect["product_version_name"],
                        " ",
                        affect["component_name"],
                        component["purl"],
                        no_wrap=True,
                    )
            ctx.exit(0)

        if ctx.info_name == "products-affected-by-cve":
            console.print("link:", output["link"])
            console.print("cve_id:", output["cve_id"])
            console.print("title:", output["title"])
            console.print(
                "product_versions:",
            )
            ordered_product_versions = sorted(output["product_versions"], key=lambda d: d["name"])
            for product_version in ordered_product_versions:
                console.print(product_version["name"], no_wrap=True)
            ctx.exit(0)

        if ctx.info_name == "list":
            if "results" in output and output["count"] > 0:
                for row in output["results"]:
                    if "purl" in row:
                        console.print(row["purl"], no_wrap=True)
                    if "cve_id" in row:
                        console.print(
                            row["title"],
                            " ",
                            row["state"],
                            " ",
                            row["impact"],
                            " ",
                            row["resolution"],
                            no_wrap=True,
                        )
                    if "external_system_id" in row:
                        console.print(
                            row["external_system_id"],
                            " ",
                            row["type"],
                            " ",
                            row["status"],
                            no_wrap=True,
                        )
                    if "ofuri" in row:
                        console.print(row["name"], " ", row["ofuri"], no_wrap=True)
            ctx.exit(0)

        if ctx.info_name == "get":
            for k, v in output.items():
                key_name = Text(k)
                key_name.stylize("bold magenta")
                console.print(key_name, " : ", v, no_wrap=True)
            ctx.exit(0)

        console.print("WARNING: text version unsupported")
        ctx.exit(1)

    # if "results" in output and output["count"] > 0:
    #     et = entity_type(output["results"][0])
    #     if et == "flaw":
    #         for row in output["results"]:
    #             if "cve_id" in row:
    #                 if row["cve_id"]:
    #                     cve_id = Text(row["cve_id"])
    #                     cve_id.stylize("bold magenta")
    #                     title = row["title"].split(row["cve_id"])[1]
    #                     console.print(cve_id, " ", title, no_wrap=True)
    #             else:
    #                 if "title" in row:
    #                     console.print(title, no_wrap=True)
    #     if et == "affect":
    #         for row in output["results"]:
    #             ps_module = Text(row["ps_module"])
    #             ps_module.stylize("bold magenta")
    #             console.print(
    #                 ps_module, " ", row["ps_component"], " ", row["affectedness"], no_wrap=True
    #             )
    #     if et == "product":
    #         for row in output["results"]:
    #             product_name = Text(row["name"])
    #             product_name.stylize("bold magenta")
    #             console.print(product_name, " ", row["ofuri"], " ", no_wrap=True)
    #     if et == "component":
    #         for row in output["results"]:
    #             purl = Text(row["purl"])
    #             purl.stylize("bold magenta")
    #             console.print(purl, no_wrap=True)
    # else:
    #     for k, v in output.items():
    #         key_name = Text(k)
    #         key_name.stylize("bold magenta")
    #         console.print(key_name, " : ", v, no_wrap=True)

    if format is OUTPUT_FORMAT.TABLE:
        table = Table(title="Output")
        if "results" in output:
            for row in output["results"]:
                if "affectedness" in row:
                    table.add_row(row["ps_module"], row["ps_component"], row["affectedness"])
                if "cve_id" in row:
                    table.add_row(row["title"])
                if "purl" in row:
                    table.add_row(row["purl"])
            console.print(table)

    if format is OUTPUT_FORMAT.JSON:
        if dest is DEST.CONSOLE:
            console.print_json(json.dumps(output))

    # if we instructed to open browser, open that up now
    if ctx:
        if "link" in data and "open_browser" in ctx.obj:
            if ctx.obj["open_browser"]:
                click.launch(data["link"])

    exit(0)
