import enum
import json
import logging

import click
from packageurl import PackageURL
from rich.console import Console
from rich.text import Text

console = Console(color_system="auto")

logger = logging.getLogger("griffon")


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


def text_output_product_summary(ctx, output, format):

    ordered_results = sorted(output["results"], key=lambda d: d["name"])

    if ctx.obj["VERBOSE"] == 0:
        for item in ordered_results:
            console.print(
                Text(item["product"], style="bold magenta u"),
                Text(item["product_version"], style="magenta"),
                Text(item["name"], style="white"),
                f"{item['brew_tags']}",
                no_wrap=False,
            )
    if ctx.obj["VERBOSE"] == 1:
        for item in ordered_results:
            console.print(
                Text(item["product"], style="bold magenta u"),
                Text(item["product_version"], style="magenta"),
                Text(item["name"], style="white"),
                item["brew_tags"],
                item["ofuri"],
                no_wrap=False,
            )
    if ctx.obj["VERBOSE"] > 1:
        for item in ordered_results:
            console.print(
                Text(item["product"], style="bold magenta u"),
                Text(item["product_version"], style="magenta"),
                Text(item["name"], style="white"),
                item["brew_tags"],
                item["ofuri"],
                item["manifest_link"],
                no_wrap=False,
            )
    ctx.exit()


def text_output_products_contain_component(ctx, output, format):
    component_name = ctx.params["component_name"]

    # handle single component
    if ctx.params["purl"]:
        ordered_results = sorted(output["results"], key=lambda d: d["ofuri"])
        for item in ordered_results:
            console.print(
                Text(item["ofuri"], style="bold magenta u"),
                no_wrap=False,
            )
        ctx.exit()

    # handle multiple components
    if "results" in output and output["count"] > 0:
        ordered_results = sorted(output["results"], key=lambda d: d["product_stream"])

        if ctx.obj["VERBOSE"] == 0:  # product_version X source component
            product_versions = sorted(
                list(set([item["product_version"] for item in ordered_results]))
            )
            for pv in product_versions:
                names = []
                for item in ordered_results:
                    if pv == item["product_version"]:
                        names.append(item["name"])
                names = list(set(names))
                for name in names:
                    dep_name = name.replace(component_name, f"[b]{component_name}[/b]")
                    dep = f"[white]({dep_name})[/white]"
                    console.print(
                        Text(pv, style="magenta b u"),
                        dep,
                        no_wrap=False,
                    )
        if ctx.obj["VERBOSE"] == 1:  # product_stream X source component
            for item in ordered_results:
                dep_name = item["name"].replace(component_name, f"[b]{component_name}[/b]")
                dep = f"[white]({dep_name})[/white]"
                root_component = "[i]Root component[/i]"
                if item.get("root_component"):
                    root_component = item["root_component"]
                console.print(
                    Text(item["product_stream"], style="magenta b u"),
                    root_component,
                    dep,
                    no_wrap=False,
                )
        if ctx.obj["VERBOSE"] == 2:  # product_stream X nvr
            for item in ordered_results:
                dep_name = item["nvr"].replace(component_name, f"[b]{component_name}[/b]")
                dep = f"[white]({dep_name})[/white]"
                root_component = "[i]Root component[/i]"
                if item.get("root_component"):
                    root_component = item["root_component"]
                console.print(
                    Text(item["product_stream"], style="magenta b u"),
                    root_component,
                    dep,
                    no_wrap=False,
                )
        if ctx.obj["VERBOSE"] == 3:  # related url
            for item in ordered_results:
                dep_name = item["nvr"].replace(component_name, f"[b]{component_name}[/b]")
                dep = f"[white]({dep_name})[/white]"
                root_component = "[i]Root component[/i]"
                if item.get("root_component"):
                    root_component = item["root_component"]
                console.print(
                    Text(item["product_stream"], style="magenta b u"),
                    root_component,
                    dep,
                    item["related_url"],
                    no_wrap=False,
                )
        if ctx.obj["VERBOSE"] == 4:  # source url
            for item in ordered_results:
                dep_name = item["nvr"].replace(component_name, f"[b]{component_name}[/b]")
                dep = f"[white]({dep_name})[/white]"
                root_component = "[i]Root component[/i]"
                if item.get("root_component"):
                    root_component = item["root_component"]
                console.print(
                    Text(item["product_stream"], style="magenta b u"),
                    root_component,
                    dep,
                    item["related_url"],
                    item["build_source_url"],
                    no_wrap=False,
                )
        if ctx.obj["VERBOSE"] > 4:  # source url, upstream
            for item in ordered_results:
                dep_name = item["nvr"].replace(component_name, f"[b]{component_name}[/b]")
                dep = f"[white]({dep_name})[/white]"
                root_component = "[i]Root component[/i]"
                if item.get("root_component"):
                    root_component = item["root_component"]
                console.print(
                    Text(item["product_stream"], style="magenta b u"),
                    root_component,
                    dep,
                    item["related_url"],
                    item["build_source_url"],
                    item["upstream_purl"],
                    no_wrap=False,
                )
        ctx.exit()


def text_output_components_contain_component(ctx, output, format):
    if "results" in output:

        for item in output["results"]:
            component_name = item["name"]

            if ctx.obj["VERBOSE"] == 0:
                ordered_sources = sorted(item["sources"], key=lambda d: d["purl"])
                for source in ordered_sources:
                    if "arch=noarch" in source["purl"] or "arch=src" in source["purl"]:
                        source_purl = PackageURL.from_string(source["purl"])
                        root_component = source_purl.name
                        if source_purl.type == "oci" and "-source" not in source_purl.name:
                            root_component = f"[u magenta]{source_purl.name}-container[/u magenta]"
                        console.print(
                            root_component,
                            component_name,
                            no_wrap=False,
                        )
    ctx.exit()


def text_output_components_affected_by_cve(ctx, output, format):
    console.print("Flaw Title:", output["title"])
    console.print(
        "affects:",
    )
    ordered_affects = sorted(output["affects"], key=lambda d: d["product_version_name"])
    for affect in ordered_affects:
        if "components" in affect:
            for component in affect["components"]:
                affected_component1 = f"({component['purl']})"
                if not ctx.obj["SHOW_PURL"]:
                    purl = PackageURL.from_string(component["purl"])
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


def text_output_products_affected_by_cve(ctx, output, format):
    console.print("[white]link:[/white]", output["link"])
    console.print("[white]cve_id:[/white]", output["cve_id"])
    console.print("[white]title:[/white]", output["title"])
    console.print(
        "[white]product_versions:[/white]",
    )
    if ctx.obj["VERBOSE"] == 0:
        ordered_product_versions = sorted(output["product_versions"], key=lambda d: d["name"])
        for product_version in ordered_product_versions:
            console.print(Text(product_version["name"], style="bold magenta u"), no_wrap=True)
    if ctx.obj["VERBOSE"] > 0:
        ordered_affects = sorted(output["affects"], key=lambda d: d["product_version_name"])
        for affect in ordered_affects:
            console.print(
                Text(affect["product_version_name"], style="bold magenta u"),
                affect["component_name"],
                no_wrap=True,
            )
    ctx.exit()


def text_output_get_manifest(ctx, output, format):
    if not ctx.obj["SHOW_PURL"]:
        for component in output["packages"]:
            if "pkg:" in component["externalRefs"][0]["referenceLocator"]:
                purl = PackageURL.from_string(component["externalRefs"][0]["referenceLocator"])
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
            purl = component["externalRefs"][0]["referenceLocator"]
            console.print(purl, no_wrap=False)  # noqa

    ctx.exit()


def text_output_component_flaws(ctx, output, format):
    ordered_components = sorted(output["results"], key=lambda d: d["name"])
    for item in ordered_components:
        component_name = item["name"]
        # sorting should work when there is no title or cve-id key
        ordered_affects = sorted(item["affects"], key=lambda d: (d["title"] is None, d["title"]))
        for affect in ordered_affects:
            flaw_cve_id = "Vulnerability"
            if affect["flaw_cve_id"]:
                flaw_cve_id = affect["flaw_cve_id"]
            if ctx.obj["VERBOSE"] == 0:
                console.print(
                    Text(flaw_cve_id, style="magenta"),
                    Text(component_name, style="white"),
                    affect["affect_affectedness"],
                    affect["affect_impact"],
                    affect["affect_resolution"],
                    no_wrap=True,
                )
            if ctx.obj["VERBOSE"] == 1:
                console.print(
                    Text(flaw_cve_id, style="magenta"),
                    Text(component_name, style="white"),
                    f"(state: {affect['flaw_state']} resolution:{affect['flaw_resolution']})",
                    Text(affect["affect_product_version"], style="cyan"),
                    affect["affect_affectedness"],
                    affect["affect_impact"],
                    affect["affect_resolution"],
                    no_wrap=True,
                )
            if ctx.obj["VERBOSE"] > 1:
                console.print(Text(affect["title"], style="white"))
                console.print(
                    Text(component_name, style="magenta"),
                    f"(state: {affect['flaw_state']} resolution:{affect['flaw_resolution']})",
                    Text(affect["affect_product_version"], style="cyan"),
                    affect["affect_affectedness"],
                    affect["affect_impact"],
                    affect["affect_resolution"],
                    no_wrap=True,
                )
    ctx.exit()


def text_output_product_flaws(ctx, output, format):
    for item in output["results"]:
        component_name = item["name"]
        for affect in item["affects"]:
            if ctx.obj["VERBOSE"] == 0:
                console.print(
                    Text(affect["flaw_cve_id"], style="magenta"),
                    Text(component_name, style="white"),
                    affect["affect_name"],
                    affect["affect_affectedness"],
                    affect["affect_impact"],
                    affect["affect_resolution"],
                    no_wrap=True,
                )
            if ctx.obj["VERBOSE"] == 1:
                console.print(
                    Text(affect["flaw_cve_id"], style="magenta"),
                    Text(component_name, style="white"),
                    f"(state: {affect['flaw_state']} resolution:{affect['flaw_resolution']})",
                    affect["affect_name"],
                    affect["affect_affectedness"],
                    affect["affect_impact"],
                    affect["affect_resolution"],
                    no_wrap=True,
                )
            if ctx.obj["VERBOSE"] > 1:
                console.print(affect["title"])
                console.print(
                    Text(component_name, style="white"),
                    f"(state: {affect['flaw_state']} resolution:{affect['flaw_resolution']})",
                    affect["affect_name"],
                    affect["affect_affectedness"],
                    affect["affect_impact"],
                    affect["affect_resolution"],
                    no_wrap=True,
                )
    ctx.exit()


def text_output_list(ctx, output, format):
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
                console.print(
                    Text(row["name"], style="magenta bold u"),
                    row["ofuri"],
                    no_wrap=True,
                )
    ctx.exit()


def text_output_generic(ctx, output, format):
    for k, v in output.items():
        key_name = Text(k)
        key_name.stylize("bold magenta")
        console.print(key_name, " : ", v, no_wrap=True)


def cprint(
    data,
    dest=DEST.CONSOLE,
    filename=None,
    ctx=None,
    show_count: bool = True,
):
    """handle format and output"""
    output = raw_json_transform(data, show_count)
    console = Console(color_system="auto")
    if ctx.obj and ctx.obj["NO_COLOR"]:
        console = Console(color_system=None)
    format = OUTPUT_FORMAT.JSON
    if ctx and "FORMAT" in ctx.obj:
        format = OUTPUT_FORMAT(ctx.obj["FORMAT"])

    if format is OUTPUT_FORMAT.TEXT:
        if ctx.info_name == "product-summary":
            text_output_product_summary(ctx, output, format)
        if ctx.info_name == "products-contain-component":
            text_output_products_contain_component(ctx, output, format)
        if ctx.info_name == "components-contain-component":
            text_output_components_contain_component(ctx, output, format)
        if ctx.info_name == "components-affected-by-cve":
            text_output_components_affected_by_cve(ctx, output, format)
        if ctx.info_name == "products-affected-by-cve":
            text_output_products_affected_by_cve(ctx, output, format)
        if ctx.info_name == "get-manifest":
            text_output_get_manifest(ctx, output, format)
        if ctx.info_name == "list":
            text_output_list(ctx, output, format)
        if ctx.info_name == "component-flaws":
            text_output_component_flaws(ctx, output, format)
        if ctx.info_name == "product-flaws":
            text_output_product_flaws(ctx, output, format)

        # last chance text formatted output
        text_output_generic(ctx, output, format)

    if format is OUTPUT_FORMAT.JSON:
        if dest is DEST.CONSOLE:
            console.print_json(json.dumps(output))

    # if we instructed to open browser, open that up now
    if ctx:
        if "link" in data and "open_browser" in ctx.obj:
            if ctx.obj["open_browser"]:
                click.launch(data["link"])

    exit(0)
