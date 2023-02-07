import enum
import json
import logging

import click
from rich.console import Console

console = Console()

logger = logging.getLogger("rich")


class OUTPUT_FORMAT(enum.Enum):
    JSON = "json"
    TEXT = "text"
    TABLE = "table"


class DEST(enum.Enum):
    CONSOLE = "console"
    FILE = "file"


def raw_json_transform(data, show_count: bool):
    """normalise all data to raw json"""
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
    return json.dumps(output)


def cprint(
    data,
    dest=DEST.CONSOLE,
    format: OUTPUT_FORMAT = OUTPUT_FORMAT.JSON,
    filename: str = None,
    ctx=None,
    show_count: bool = True,
):
    """handle format and output"""
    output = raw_json_transform(data, show_count)
    if format is OUTPUT_FORMAT.JSON:
        if dest is DEST.CONSOLE:
            console.print_json(output)
    else:
        if dest is DEST.CONSOLE:
            console.print_json(output)
        if ctx:
            if "link" in data and "open_browser" in ctx.obj:
                if ctx.obj["open_browser"]:
                    click.launch(data["link"])
