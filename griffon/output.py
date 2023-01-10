import json

import click
from rich.console import Console

console = Console()


def cprint(data, dest="console", format="json", filename=None, ctx=None, show_count=True):
    """handle format and output"""
    if type(data) == list:
        results = []
        for d in data:
            if type(d) is dict:
                results.append(d)
            else:
                results.append(d.to_dict())
        output = {
            "results": results,
            "count": len(data),
        }
        if show_count:
            output["count"] = len(data)
        console.print_json(json.dumps(output))
    else:
        try:
            console.print_json(json.dumps(data))
        except Exception as exc:  # noqa
            console.print_json(json.dumps(data.to_dict()))
        if ctx:
            if "link" in data and "open_browser" in ctx.obj:
                if ctx.obj["open_browser"]:
                    click.launch(data["link"])
