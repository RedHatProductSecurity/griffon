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


def raw_json_transform(data, show_count: bool):
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
            output["count"] = len(results)
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
    filename: str = None,
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
        if "results" in output and output["count"] > 0:
            et = entity_type(output["results"][0])
            if et == "flaw":
                for row in output["results"]:
                    if "cve_id" in row:
                        if row["cve_id"]:
                            cve_id = Text(row["cve_id"])
                            cve_id.stylize("bold magenta")
                            title = row["title"].split(row["cve_id"])[1]
                            console.print(cve_id, " ", title, no_wrap=True)
                    else:
                        if "title" in row:
                            console.print(title, no_wrap=True)
            if et == "affect":
                for row in output["results"]:
                    ps_module = Text(row["ps_module"])
                    ps_module.stylize("bold magenta")
                    console.print(
                        ps_module, " ", row["ps_component"], " ", row["affectedness"], no_wrap=True
                    )
            if et == "product":
                for row in output["results"]:
                    product_name = Text(row["name"])
                    product_name.stylize("bold magenta")
                    console.print(product_name, " ", row["ofuri"], " ", no_wrap=True)
            if et == "component":
                for row in output["results"]:
                    purl = Text(row["purl"])
                    purl.stylize("bold magenta")
                    console.print(purl, no_wrap=True)
        else:
            for k, v in output.items():
                key_name = Text(k)
                key_name.stylize("bold magenta")
                console.print(key_name, " : ", v, no_wrap=True)

    if format is OUTPUT_FORMAT.TABLE:
        table = Table(title="Output")
        if type(output) == list:
            pass
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
