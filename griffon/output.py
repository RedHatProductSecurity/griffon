import enum
import json
import logging

import click
from packageurl import PackageURL
from rich.console import Console
from rich.text import Text

console = Console(color_system="auto")

logger = logging.getLogger("rich")


class OUTPUT_FORMAT(enum.Enum):
    JSON = "json"
    TEXT = "text"
    TABLE = "table"


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


def component_type_style(type):
    from griffon import CorgiService

    types = [type.value for type in CorgiService.get_component_types()]
    colors = (
        "cornflower_blue",
        "red",
        "dark_slate_gray1",
        "magenta",
        "navy_blue",
        "green1",
        "blue",
        "dark_orange",
        "deep_pink1",
        "red1",
        "green1",
    )
    color = colors[types.index(type)]
    return f"[{color}]{type}[/{color}]"


def cprint(
    data,
    dest=DEST.CONSOLE,
    filename=None,
    ctx=None,
    show_count: bool = True,
):
    """handle format and output"""
    from griffon.autocomplete import get_product_stream_names, get_product_stream_ofuris

    output = raw_json_transform(data, show_count)
    allowed_product_stream_names = get_product_stream_names(ctx, None, "")
    allowed_product_stream_ofuris = get_product_stream_ofuris(ctx, None, "")
    console = Console(color_system="auto")
    if ctx.obj and ctx.obj["NO_COLOR"]:
        console = Console(color_system=None)
    format = OUTPUT_FORMAT.JSON
    if ctx and "FORMAT" in ctx.obj:
        format = OUTPUT_FORMAT(ctx.obj["FORMAT"])

    if format is OUTPUT_FORMAT.TEXT:
        # TODO - we will refactor this areato use full featured templating ... opting for
        #    simple for now ... will DRY this once it stabilises.

        if ctx.info_name == "product-summary":
            for k, v in output.items():
                key_name = Text(k, style="bold magenta")
                console.print(key_name, " : ", v, no_wrap=True)
            ctx.exit()

        if ctx.info_name == "products-contain-component":
            if ctx.params["purl"]:
                ordered_results = sorted(output["results"], key=lambda d: d["ofuri"])
                for item in ordered_results:
                    if item["ofuri"] in allowed_product_stream_ofuris:
                        console.print(
                            Text(item["ofuri"], style="bold magenta u"),
                            no_wrap=False,
                        )
                ctx.exit()

            if "results" in output and output["count"] > 0:
                ordered_results = sorted(output["results"], key=lambda d: d["name"])
                for item in ordered_results:
                    if ctx.obj["SHOW_UPSTREAM"] or (
                        "redhat" in item["component_purl"] and not ctx.obj["SHOW_UPSTREAM"]
                    ):
                        if item["name"] in allowed_product_stream_names:
                            component = f"({item['component_purl']})"
                            ns = ""
                            arch = ""
                            related_url = item["component_related_url"] or ""
                            if not ctx.obj["SHOW_PURL"]:
                                purl = PackageURL.from_string(item["component_purl"])
                                component = f"([bold turquoise2]{ns}[/bold turquoise2] [white]{purl.name}-{purl.version}[/white],{component_type_style(purl.type.upper())})"  # noqa
                                if purl.qualifiers:
                                    if "arch" in purl.qualifiers and ctx.obj["VERBOSE"] > 0:
                                        arch = purl.qualifiers["arch"]
                                ns = "UPSTREAM"
                                if purl.namespace:
                                    ns = purl.namespace.upper()
                                    component = f"([white]{ns}[/white] [white]{purl.name}-{purl.version}[/white],{arch},{component_type_style(purl.type.upper())})"  # noqa
                                if purl.namespace == "redhat":
                                    ns = purl.namespace.upper()
                                    component = f"([bold red]{ns}[/bold red] [white]{purl.name}-{purl.version}[/white],{arch},{component_type_style(purl.type.upper())})"  # noqa

                            source_url = ""
                            if "source" in item["component_software_build"]:
                                source_url = item["component_software_build"].get("source")
                            root_components = item["component_root_components"]
                            if root_components:
                                for component_root_component in root_components:
                                    root_component = component_root_component
                                    if not ctx.obj["SHOW_PURL"]:
                                        purl = PackageURL.from_string(component_root_component)
                                        root_component = purl.name
                                        if ctx.obj["VERBOSE"] > 0:
                                            root_component = f"{purl.name}-{purl.version}"
                                    if ctx.obj["VERBOSE"] == 0:
                                        console.print(
                                            Text(item["name"], style="bold magenta u"),
                                            Text(root_component, style="white"),
                                            component,
                                            no_wrap=False,
                                        )
                                    if ctx.obj["VERBOSE"] == 1:
                                        console.print(
                                            Text(item["name"], style="bold magenta u"),
                                            Text(root_component, style="white"),
                                            component,
                                            related_url,
                                            no_wrap=False,
                                        )
                                        console.print()
                                    if ctx.obj["VERBOSE"] > 1:
                                        purl = PackageURL.from_string(item["component_purl"])
                                        console.print(
                                            Text(item["name"], style="bold magenta u"),
                                            Text(root_component, style="white"),
                                            component,
                                            related_url,
                                            Text(source_url, style="i"),
                                            no_wrap=False,
                                        )
                            else:
                                if not ctx.obj["SHOW_PURL"]:
                                    purl = PackageURL.from_string(item["component_purl"])
                                    component = f"([bold turquoise2]{ns}[/bold turquoise2] [white]{purl.name}-{purl.version}[/white],{component_type_style(purl.type.upper())})"  # noqa
                                    if purl.qualifiers:
                                        if "arch" in purl.qualifiers and ctx.obj["VERBOSE"] > 0:
                                            arch = purl.qualifiers["arch"]
                                    ns = "UPSTREAM"
                                    if purl.namespace:
                                        ns = purl.namespace.upper()
                                        component = f"([white]{ns}[/white] [white]{purl.name}-{purl.version}[/white],{arch},{component_type_style(purl.type.upper())})"  # noqa
                                    if purl.namespace == "redhat":
                                        ns = purl.namespace.upper()
                                        component = f"([bold red]{ns}[/bold red] [white]{purl.name}-{purl.version}[/white],{arch},{component_type_style(purl.type.upper())})"  # noqa

                                if ctx.obj["VERBOSE"] == 0:
                                    console.print(
                                        Text(item["name"], style="bold magenta u"),
                                        Text("none", style="white"),
                                        component,
                                        no_wrap=False,
                                    )
                                if ctx.obj["VERBOSE"] == 1:
                                    console.print(
                                        Text(item["name"], style="bold magenta u"),
                                        Text("none", style="white"),
                                        component,
                                        related_url,
                                        no_wrap=False,
                                    )
                                    console.print()
                                if ctx.obj["VERBOSE"] > 1:
                                    console.print(
                                        Text(item["name"], style="bold magenta u"),
                                        Text("none", style="white"),
                                        component,
                                        related_url,
                                        Text(source_url, style="i"),
                                        no_wrap=False,
                                    )
                ctx.exit()
                # TODO - need specific purl output

        if ctx.info_name == "components-contain-component":
            if "results" in output:
                for item in output["results"]:
                    if ctx.obj["SHOW_UPSTREAM"] or (
                        "redhat" in item["purl"] and not ctx.obj["SHOW_UPSTREAM"]
                    ):
                        component = item["purl"]
                        if not ctx.obj["SHOW_PURL"]:
                            purl = PackageURL.from_string(item["purl"])
                            ns = "UPSTREAM"
                            component = f"([bold turquoise2]{ns}[/bold turquoise2] [white]{purl.name}-{purl.version}[/white],{component_type_style(purl.type.upper())})"  # noqa
                            if purl.namespace == "redhat":
                                ns = purl.namespace.upper()
                                component = f"([bold red]{ns}[/bold red] [white]{purl.name}-{purl.version}[/white],{component_type_style(purl.type.upper())})"  # noqa
                            if purl.namespace:
                                ns = purl.namespace.upper()
                                component = f"([white]{ns}[/white] [white]{purl.name}-{purl.version}[/white],{component_type_style(purl.type.upper())})"  # noqa
                        ordered_sources = sorted(item["sources"], key=lambda d: d["purl"])
                        for source in ordered_sources:
                            root_component = source["purl"]
                            if not ctx.obj["SHOW_PURL"]:
                                purl = PackageURL.from_string(source["purl"])
                                root_component = (
                                    f"[u magenta]{purl.name}-{purl.version}[/u magenta]"
                                )

                            if ctx.obj["VERBOSE"] == 0:
                                console.print(
                                    root_component,
                                    component,
                                    no_wrap=False,
                                )
                            if ctx.obj["VERBOSE"] == 1:
                                console.print(
                                    root_component,
                                    component,
                                    no_wrap=False,
                                )
                ctx.exit()

        if ctx.info_name == "components-affected-by-cve":
            console.print("Flaw Title:", output["title"])
            console.print(
                "affects:",
            )
            ordered_affects = sorted(output["affects"], key=lambda d: d["product_version_name"])
            for affect in ordered_affects:
                if "components" in affect:
                    for component in affect["components"]:
                        affected_component1 = f"({component['purl']})"  # type: ignore
                        if not ctx.obj["SHOW_PURL"]:
                            purl = PackageURL.from_string(component["purl"])  # type: ignore
                            ns = "UPSTREAM"
                            if purl.namespace:
                                ns = purl.namespace.upper()
                            affected_component1 = f"([bold cyan]{ns}[/bold cyan] {purl.name}-{purl.version},{purl.type.upper()})"  # noqa
                            if ctx.obj["VERBOSE"] == 0:
                                console.print(
                                    ns,
                                    affected_component1,
                                    no_wrap=True,
                                )
                            if ctx.obj["VERBOSE"] == 1:
                                console.print(
                                    ns,
                                    affected_component1,
                                    no_wrap=True,
                                )
            ctx.exit()

        if ctx.info_name == "products-affected-by-cve":
            console.print("[white]link:[/white]", output["link"])
            console.print("[white]cve_id:[/white]", output["cve_id"])
            console.print("[white]title:[/white]", output["title"])
            console.print(
                "[white]product_versions:[/white]",
            )
            if ctx.obj["VERBOSE"] == 0:
                ordered_product_versions = sorted(
                    output["product_versions"], key=lambda d: d["name"]
                )
                for product_version in ordered_product_versions:
                    console.print(
                        Text(product_version["name"], style="bold magenta u"), no_wrap=True
                    )
            if ctx.obj["VERBOSE"] > 0:
                ordered_affects = sorted(output["affects"], key=lambda d: d["product_version_name"])
                for affect in ordered_affects:
                    console.print(
                        Text(affect["product_version_name"], style="bold magenta u"),
                        affect["component_name"],
                        no_wrap=True,
                    )
            ctx.exit()

        if ctx.info_name == "get-manifest":
            if not ctx.obj["SHOW_PURL"]:
                for component in output["packages"]:
                    if "pkg:" in component["externalRefs"][0]["referenceLocator"]:  # type: ignore
                        purl = PackageURL.from_string(
                            component["externalRefs"][0]["referenceLocator"]  # type: ignore
                        )
                        ns = "[cyan]UPSTREAM[/cyan]"
                        component = f"([bold turquoise2]{ns}[/bold turquoise2] [white]{purl.name}-{purl.version}[/white],{component_type_style(purl.type.upper())})"  # noqa
                        if purl.namespace == "redhat":
                            ns = f"[red]{purl.namespace.upper()}[/red]"
                            component = f"([white]{purl.name}-{purl.version}[/white],{component_type_style(purl.type.upper())})"  # noqa
                        else:
                            if purl.namespace:
                                ns = f"[white]{purl.namespace.upper()}[/white]"
                            component = f"([white]{purl.name}-{purl.version}[/white],{component_type_style(purl.type.upper())})"  # noqa
                        console.print(ns, component, no_wrap=False)  # noqa
            else:
                for component in output["packages"]:
                    purl = component["externalRefs"][0]["referenceLocator"]  # type: ignore
                    console.print(purl, no_wrap=False)  # noqa

            ctx.exit()

        if ctx.info_name == "list":
            if "results" in output and output["count"] > 0:

                # handle component
                if "purl" in output["results"][0]:
                    ordered_components = sorted(output["results"], key=lambda d: d["name"])
                    for row in ordered_components:
                        if "purl" in row:
                            purl = PackageURL.from_string(row["purl"])
                            if not purl.namespace:
                                component_ns = Text("UPSTREAM", style="bold magenta")
                            else:
                                component_ns = Text(purl.namespace.upper(), style="bold red")

                            if not ctx.obj["SHOW_PURL"]:
                                console.print(
                                    component_ns,
                                    purl.type.upper(),
                                    Text(purl.name, style="bold white"),
                                    purl.version,
                                    row["related_url"],
                                    purl.qualifiers.get("arch"),
                                )
                            else:
                                console.print(
                                    row["purl"],
                                )
                # handle flaw
                if "cve_id" in output["results"][0]:
                    for row in output["results"]:
                        console.print(
                            row["title"],
                            row["state"],
                            row["impact"],
                            row["resolution"],
                            no_wrap=True,
                        )

                # handle trackers
                if "external_system_id" in output["results"][0]:
                    for row in output["results"]:
                        console.print(
                            row["external_system_id"],
                            row["type"],
                            row["status"],
                            no_wrap=True,
                        )

                # handle products
                if "ofuri" in output["results"][0]:
                    for row in output["results"]:
                        if row["name"] in allowed_product_stream_names:
                            console.print(
                                Text(row["name"], style="magenta bold u"),
                                row["ofuri"],
                                no_wrap=True,
                            )
            ctx.exit()

        # handle empty results
        if "results" in output and output["count"] == 0:
            console.print("No results")
            ctx.exit()

        # last ditch formatting on unknown
        for k, v in output.items():
            key_name = Text(k)
            key_name.stylize("bold magenta")
            console.print(key_name, " : ", v, no_wrap=True)
        console.print("WARNING: using generic text format (try --format json).")

    if format is OUTPUT_FORMAT.TABLE:
        pass

    if format is OUTPUT_FORMAT.JSON:
        if dest is DEST.CONSOLE:
            console.print_json(json.dumps(output))

    # if we instructed to open browser, open that up now
    if ctx:
        if "link" in data and "open_browser" in ctx.obj:
            if ctx.obj["open_browser"]:
                click.launch(data["link"])

    exit(0)
