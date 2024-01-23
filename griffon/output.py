"""
    Gather up all of the messy 'presentation' logic into one place

"""
import enum
import json
import logging
import re

import click
from component_registry_bindings.bindings.python_client.types import (
    ComponentRegistryModel,
)
from packageurl import PackageURL
from rich.console import Console
from rich.text import Text
from rich.tree import Tree

console = Console(color_system="auto")

logger = logging.getLogger("griffon")


class OUTPUT_FORMAT(enum.Enum):
    JSON = "json"
    TEXT = "text"
    TABLE = "table"


class DEST(enum.Enum):
    CONSOLE = "console"
    FILE = "file"


def raw_json_transform_related(data: dict, name):
    """normalise ralated data which were piggy-backed to data"""
    transformed = []
    related_data = data.get(name)
    if related_data is not None:
        if isinstance(related_data, list):
            transformed = [
                item.to_dict() if isinstance(item, ComponentRegistryModel) else item
                for item in related_data
            ]

    return transformed


def raw_json_transform(data, show_count: bool) -> dict:
    """normalise all data to dict"""
    if type(data) is list:
        results = []
        for item in data:
            transformed = item if type(item) is dict else item.to_dict()
            for related_data in ("upstreams", "sources", "provides"):
                if related_data in transformed:
                    transformed[related_data] = raw_json_transform_related(
                        transformed, related_data
                    )
            results.append(transformed)
        output = {
            "results": results,
        }
        if show_count:
            output["count"] = len(results)  # type: ignore
    else:
        output = data if type(data) is dict else data.to_dict()
        for related_data in ("upstreams", "sources", "provides"):
            if related_data in output:
                output[related_data] = raw_json_transform_related(output, related_data)
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


def output_version(ctx, version):
    if version:
        if version.startswith("sha256") and ctx.obj["SHORT_VERSION_VALUES"]:
            return f"sha256...{version[-8:]}"
    return version


def walk_component_tree(obj, key, tree, show_purl=False):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                walk_component_tree(v, k, tree, show_purl=show_purl)
    elif isinstance(obj, list):
        for item in obj:
            label = f"{item['node_type']}: {item['nvr']},{item['type']}"
            if show_purl:
                label = f"{item['node_type']}: {item['purl']}"
            child = tree.add(label)
            walk_component_tree(item, None, child, show_purl=show_purl)
    return tree


def text_output_tree(ctx, output, no_wrap=False):
    tree = Tree(
        "component dependency tree",
        guide_style="bold magenta",
    )
    console.print(walk_component_tree(output, None, tree, show_purl=ctx.params["show_purl"]))
    ctx.exit()


def text_output_product_summary(ctx, output, format, exclude_products, no_wrap=False):
    ordered_results = sorted(output["results"], key=lambda d: d["name"])

    if exclude_products:
        exclude_products_results = []
        for result in ordered_results:
            if not any([re.search(match, result["product_version"]) for match in exclude_products]):
                exclude_products_results.append(result)
        ordered_results = exclude_products_results

    if ctx.obj["VERBOSE"] == 0:
        for item in ordered_results:
            console.print(
                Text(item["product"], style="bold magenta u"),
                Text(item["product_version"], style="magenta"),
                Text(item["name"], style="white"),
                f"{item['brew_tags']}",
                no_wrap=no_wrap,
            )
    if ctx.obj["VERBOSE"] == 1:
        for item in ordered_results:
            console.print(
                Text(item["product"], style="bold magenta u"),
                Text(item["product_version"], style="magenta"),
                Text(item["name"], style="white"),
                item["brew_tags"],
                item["ofuri"],
                no_wrap=no_wrap,
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
                no_wrap=no_wrap,
            )
    ctx.exit()


def process_excludes_condition(
    exclude_products,
    ps_exclude_components,
    exclude_components,
    ps_version_name,
    component_name,
    include_product_stream_excluded_components,
):
    # .griffonrc defined exclude product streams
    if not any([re.search(match, ps_version_name) for match in exclude_products]):
        # product stream defined exclude components
        if (
            not any([re.search(match, component_name) for match in ps_exclude_components])
            or include_product_stream_excluded_components
        ):
            # .griffonrc defined exclude components
            if not any([re.search(match, component_name) for match in exclude_components]):
                return True
        return False


def generate_normalised_results(
    output,
    exclude_products,
    exclude_components,
    output_type_filter,
    include_inactive_product_streams,
    include_product_stream_excluded_components,
):
    normalised_results = list()
    if "results" in output:
        # ensure unique result set
        seen = set()
        results = []
        for obj in output["results"]:
            if "purl" in obj:
                if obj["purl"] not in seen:
                    seen.add(obj["purl"])
                    results.append(obj)
            else:
                if obj["nvr"] not in seen:
                    seen.add(obj["nvr"])
                    results.append(obj)
        for item in output["results"]:
            for ps in item["product_streams"]:
                # only include component from active product stream
                if ps.get("active") or include_inactive_product_streams:
                    if process_excludes_condition(
                        exclude_products,
                        ps.get("exclude_components", []),
                        exclude_components,
                        ps["product_versions"][0]["name"],
                        item["name"],
                        include_product_stream_excluded_components,
                    ):
                        c = {
                            "product_version": ps["product_versions"][0]["name"],
                            "product_stream": ps.get("name"),
                            "product_stream_active": ps.get("active"),
                            "product_stream_relations": ps.get("relations"),
                            "namespace": item.get("namespace"),
                            "name": item.get("name"),
                            "nvr": item.get("nvr"),
                            "type": item.get("type"),
                            "arch": item.get("arch"),
                            "version": item.get("version"),
                            "related_url": item.get("related_url"),
                            "purl": item.get("purl"),
                        }
                        if "software_build" in item:
                            c["build_source_url"] = item["software_build"].get("source")
                            c["build_type"] = item["software_build"].get("build_type")

                        if "sources" in item:
                            sources = []
                            for source in item.get("sources"):
                                if process_excludes_condition(
                                    exclude_products,
                                    ps.get("exclude_components", []),
                                    exclude_components,
                                    ps["product_versions"][0]["name"],
                                    source["name"],
                                    include_product_stream_excluded_components,
                                ):
                                    sources.append(source)
                            c["sources"] = sources

                        if "upstreams" in item:
                            upstreams = []
                            for upstream in item.get("upstreams"):
                                if process_excludes_condition(
                                    exclude_products,
                                    ps.get("exclude_components", []),
                                    exclude_components,
                                    ps["product_versions"][0]["name"],
                                    upstream["name"],
                                    include_product_stream_excluded_components,
                                ):
                                    upstreams.append(upstream)
                            c["upstreams"] = upstreams

                        if "provides" in item:
                            provides = []
                            for provide in item.get("provides"):
                                if process_excludes_condition(
                                    exclude_products,
                                    ps.get("exclude_components", []),
                                    exclude_components,
                                    ps["product_versions"][0]["name"],
                                    provide["name"],
                                    include_product_stream_excluded_components,
                                ):
                                    provides.append(provide)
                            c["provides"] = provides

                        # output type filter
                        if output_type_filter is None:
                            normalised_results.append(c)
                        if item.get("type") == output_type_filter:
                            normalised_results.append(c)
    return normalised_results


def generate_result_tree(normalised_results):
    product_versions = sorted(list(set([item["product_version"] for item in normalised_results])))
    result_tree = {}
    for pv in product_versions:
        result_tree[pv] = {}
        product_streams = sorted(
            list(
                set(
                    [
                        item["product_stream"]
                        for item in normalised_results
                        if item["product_version"] == pv
                    ]
                )
            )
        )
        for ps in product_streams:
            result_tree[pv][ps] = {}
            component_names = sorted(
                list(
                    set(
                        [
                            item["name"]
                            for item in normalised_results
                            if item["product_stream"] == ps
                        ]
                    )
                )
            )
            for cn in component_names:
                result_tree[pv][ps][cn] = {}
                nvrs = [
                    item
                    for item in normalised_results
                    if item["product_stream"] == ps and item["name"] == cn
                ]

                for nvr in nvrs:
                    result_tree[pv][ps][cn][nvr["nvr"]] = nvr
    return result_tree


def generate_affects(
    ctx, result_tree, exclude_components, flaw_operation, format="text", no_wrap=False
):
    search_component_name = ctx.params["component_name"]
    affects = []

    for pv in result_tree.keys():
        component_names = set()
        for ps in result_tree[pv].keys():
            for component_name in result_tree[pv][ps].keys():
                for nvr in result_tree[pv][ps][component_name].keys():
                    if result_tree[pv][ps][component_name][nvr]["sources"]:
                        source_names = [
                            source["name"]
                            for source in result_tree[pv][ps][component_name][nvr]["sources"]
                            if source.namespace == "REDHAT"
                        ]
                        component_names.update(source_names)
                    else:
                        if ctx.params["no_upstream_affects"]:
                            if result_tree[pv][ps][component_name][nvr]["namespace"] == "REDHAT":
                                component_names.add(component_name)
                        else:
                            component_names.add(component_name)

        # we should only show component name if both {component name} and {component name-container} exists # noqa
        if (
            search_component_name in component_names
            and f"{search_component_name}-container" in component_names
        ):
            component_names.remove(f"{search_component_name}-container")
        if format == "text":
            for cn in component_names:
                # ensure {component name} is not in profile exclude components enum
                if not any([re.search(match, cn) for match in exclude_components]):
                    console.print(
                        f"{pv}/{cn}={flaw_operation}",
                        no_wrap=no_wrap,
                    )
        else:
            for cn in component_names:
                # ensure {component name} is not in profile exclude components enum
                if not any([re.search(match, cn) for match in exclude_components]):
                    affects.append(
                        {"product_version": pv, "component_name": cn, "operation": flaw_operation}
                    )
    return affects


def process_component_color(namespace: str, build_type: str) -> str:
    """return color used for component, currently only based on component build type"""
    if namespace:
        if namespace == "UPSTREAM":
            return "u"
    if build_type:
        if build_type == "PYXIS":
            return "green"
    return "grey93"


def process_product_color(relations: str, build_type: str) -> str:
    """return color used for product, currently only based on relations"""
    if relations:
        relations_types = [relation["type"] for relation in relations]
        if "APP_INTERFACE" in relations_types:
            return "blue"
    if build_type:
        if build_type == "PYXIS":
            return "green"
        if build_type == "PNC":
            return "red"
        if build_type == "KOJI":
            return "yellow"
        if build_type == "CENTOS":
            return "yellow"
    return "magenta"


def highlight_search_term(search_pattern, text_value):
    return re.sub(search_pattern, "[b]\\g<0>[/b]", text_value)


def text_output_products_contain_component(
    ctx,
    output,
    exclude_products,
    exclude_components,
    no_wrap=False,
):
    # handle single component
    if ctx.params["purl"]:
        ordered_results = sorted(output["results"], key=lambda d: d["ofuri"])
        for item in ordered_results:
            console.print(
                Text(item["ofuri"], style="bold magenta u"),
                no_wrap=no_wrap,
            )
        ctx.exit()

    search_component_name = ctx.params["component_name"]

    # handle multiple components
    if "results" in output and output["count"] > 0:
        console.highlighter = None

        # first flatten the tree
        normalised_results = generate_normalised_results(
            output,
            exclude_products,
            exclude_components,
            ctx.params["output_type_filter"],
            ctx.params["include_inactive_product_streams"],
            ctx.params["include_product_stream_excluded_components"],
        )
        result_tree = generate_result_tree(normalised_results)

        # TODO - MAVEN component type will require special handling
        if ctx.params["affect_mode"]:
            console.no_color = True
            console.highlighter = None

            flaw_mode = ctx.params["flaw_mode"]
            flaw_operation = "new"
            if flaw_mode == "add":
                flaw_operation = "new"
            if flaw_mode == "update":
                flaw_operation = "update"
            if flaw_mode == "dry_run":
                flaw_operation = "dry_run"

            generate_affects(ctx, result_tree, exclude_components, flaw_operation, no_wrap=False)

        else:
            if ctx.obj["VERBOSE"] == 0:  # product_version X root component nvr
                for pv in result_tree.keys():
                    for ps in result_tree[pv].keys():
                        for cn in sorted(result_tree[pv][ps].keys()):
                            # select the latest nvr (from sorted list)
                            nvr = list(result_tree[pv][ps][cn].keys())[-1]
                            product_color = process_product_color(
                                result_tree[pv][ps][cn][nvr]["product_stream_relations"],
                                result_tree[pv][ps][cn][nvr]["build_type"],
                            )
                            root_component_color = process_component_color(
                                result_tree[pv][ps][cn][nvr]["namespace"],
                                result_tree[pv][ps][cn][nvr]["build_type"],
                            )
                            dep_name = nvr
                            # highlight search term
                            try:
                                dep_name = highlight_search_term(search_component_name, dep_name)
                            except re.error:
                                pass
                            dep = f"[{root_component_color}]{dep_name}[/{root_component_color}]"  # noqa
                            if result_tree[pv][ps][cn][nvr]["upstreams"]:
                                upstream_component_names = sorted(
                                    list(
                                        [
                                            f"{upstream['name']} {upstream['version']}"
                                            for upstream in result_tree[pv][ps][cn][nvr][
                                                "upstreams"
                                            ]
                                        ]
                                    )
                                )
                                for upstream_component_name in upstream_component_names:
                                    console.print(
                                        Text(pv, style=f"{product_color} b"),
                                        f"[pale_turquoise1]{upstream_component_name}[/pale_turquoise1]",  # noqa
                                        no_wrap=no_wrap,
                                    )
                            if result_tree[pv][ps][cn][nvr]["sources"]:
                                source_component_names = sorted(
                                    list(
                                        set(
                                            [
                                                f"{source['name']} {source['version']}"
                                                for source in result_tree[pv][ps][cn][nvr][
                                                    "sources"
                                                ]
                                            ]
                                        )
                                    )
                                )
                                for source_component_name in source_component_names:
                                    console.print(
                                        Text(pv, style=f"{product_color} b"),
                                        f"[pale_turquoise1]{source_component_name}[/pale_turquoise1]",  # noqa
                                        no_wrap=no_wrap,
                                    )
                            if not (result_tree[pv][ps][cn][nvr]["upstreams"]) and not (
                                result_tree[pv][ps][cn][nvr]["sources"]
                            ):
                                console.print(
                                    Text(pv, style=f"{product_color} b"),
                                    dep,
                                    no_wrap=no_wrap,
                                    width=10000,
                                )
            if (
                ctx.obj["VERBOSE"] == 1
            ):  # product_stream X root component nvr (type) x child components [nvr (type)]
                for pv in result_tree.keys():
                    for ps in result_tree[pv].keys():
                        for cn in sorted(result_tree[pv][ps].keys()):
                            # select the latest nvr (from sorted list)
                            nvr = list(result_tree[pv][ps][cn].keys())[-1]
                            product_color = process_product_color(
                                result_tree[pv][ps][cn][nvr]["product_stream_relations"],
                                result_tree[pv][ps][cn][nvr]["build_type"],
                            )
                            root_component_color = process_component_color(
                                result_tree[pv][ps][cn][nvr]["namespace"],
                                result_tree[pv][ps][cn][nvr]["build_type"],
                            )
                            # highlight search term
                            dep_name = nvr
                            try:
                                dep_name = highlight_search_term(search_component_name, dep_name)
                            except re.error:
                                pass
                            dep = f"[{root_component_color}]{dep_name} ({result_tree[pv][ps][cn][nvr]['type']})[/{root_component_color}]"  # noqa
                            related_url = result_tree[pv][ps][cn][nvr].get("related_url")
                            try:
                                if result_tree[pv][ps][cn][nvr]["related_url"]:
                                    related_url = highlight_search_term(
                                        search_component_name,
                                        result_tree[pv][ps][cn][nvr]["related_url"],
                                    )
                            except re.error:
                                pass
                            provides_components = []
                            if "provides" in result_tree[pv][ps][cn][nvr]:
                                provides_component_names = set(
                                    [
                                        provide["name"]
                                        for provide in result_tree[pv][ps][cn][nvr]["provides"]
                                    ]
                                )
                                for provide_name in provides_component_names:
                                    versions = set(
                                        [
                                            provide["version"]
                                            for provide in result_tree[pv][ps][cn][nvr]["provides"]
                                            if provide["name"] == provide_name
                                        ]
                                    )
                                    types = set(
                                        [
                                            provide["type"]
                                            for provide in result_tree[pv][ps][cn][nvr]["provides"]
                                            if provide["name"] == provide_name
                                        ]
                                    )
                                    provides_components.append(
                                        f"{provide_name} {(','.join(versions))} ({(',').join(types)})"  # noqa
                                    )
                            if result_tree[pv][ps][cn][nvr]["upstreams"]:
                                upstream_component_names = sorted(
                                    list(
                                        set(
                                            [
                                                f"{upstream['nvr']} ({upstream['type']})"
                                                for upstream in result_tree[pv][ps][cn][nvr][
                                                    "upstreams"
                                                ]
                                            ]
                                        )
                                    )
                                )
                                if len(upstream_component_names) > 0:
                                    upstream_component_name = upstream_component_names[0]
                                    if len(upstream_component_names) > 1:
                                        upstream_component_name = f"{upstream_component_names[0]} and {len(upstream_component_names) - 1} more"  # noqa
                                    console.print(
                                        Text(ps, style=f"{product_color} b"),
                                        f"[pale_turquoise1]{upstream_component_name}[/pale_turquoise1]",  # noqa
                                        f"[{dep}]",
                                        no_wrap=no_wrap,
                                    )
                            if result_tree[pv][ps][cn][nvr]["sources"]:
                                source_component_names = sorted(
                                    list(
                                        set(
                                            [
                                                f"{source['nvr']} ({source['type']})"
                                                for source in result_tree[pv][ps][cn][nvr][
                                                    "sources"
                                                ]
                                            ]
                                        )
                                    )
                                )
                                if len(source_component_names) > 0:
                                    source_component_name = source_component_names[0]
                                    if len(source_component_names) > 1:
                                        source_component_name = f"{source_component_names[0]} and {len(source_component_names) - 1} more]"  # noqa
                                    console.print(
                                        Text(ps, style=f"{product_color} b"),
                                        f"[pale_turquoise1]{source_component_name}[/pale_turquoise1]",  # noqa
                                        f"[{dep}]",
                                        no_wrap=no_wrap,
                                    )
                            if not (result_tree[pv][ps][cn][nvr]["upstreams"]) and not (
                                result_tree[pv][ps][cn][nvr]["sources"]
                            ):
                                child_dep_names = ""
                                if provides_components:
                                    try:
                                        child_dep_names = highlight_search_term(
                                            search_component_name,
                                            ", ".join(provides_components),
                                        )
                                        child_dep_names = f"[{child_dep_names}]"
                                    except re.error:
                                        pass
                                console.print(
                                    Text(ps, style=f"{product_color} b"),
                                    dep,
                                    child_dep_names,
                                    no_wrap=no_wrap,
                                    width=10000,
                                )
            if (
                ctx.obj["VERBOSE"] == 2
            ):  # product_stream X root component nvr (type:arch) x child components [name {versions} (type:{arches})] x related_url x build_source_url # noqa
                for pv in result_tree.keys():
                    for ps in result_tree[pv].keys():
                        for cn in sorted(result_tree[pv][ps].keys()):
                            # select the latest nvr (from sorted list)
                            nvr = list(result_tree[pv][ps][cn].keys())[-1]
                            product_color = process_product_color(
                                result_tree[pv][ps][cn][nvr]["product_stream_relations"],
                                result_tree[pv][ps][cn][nvr]["build_type"],
                            )
                            root_component_color = process_component_color(
                                result_tree[pv][ps][cn][nvr]["namespace"],
                                result_tree[pv][ps][cn][nvr]["build_type"],
                            )
                            # highlight search term
                            dep_name = nvr
                            try:
                                dep_name = highlight_search_term(
                                    search_component_name,
                                    dep_name,
                                )
                            except re.error:
                                pass
                            dep = f"[{root_component_color}]{dep_name} ({result_tree[pv][ps][cn][nvr]['type']}:{result_tree[pv][ps][cn][nvr]['arch']})[/{root_component_color}]"  # noqa
                            related_url = result_tree[pv][ps][cn][nvr].get("related_url")
                            try:
                                if result_tree[pv][ps][cn][nvr]["related_url"]:
                                    related_url = highlight_search_term(
                                        search_component_name,
                                        result_tree[pv][ps][cn][nvr]["related_url"],
                                    )

                            except re.error:
                                pass
                            build_source_url = ""
                            if result_tree[pv][ps][cn][nvr]["build_source_url"]:
                                build_source_url = result_tree[pv][ps][cn][nvr]["build_source_url"]
                            provides_components = []
                            if "provides" in result_tree[pv][ps][cn][nvr]:
                                provides_component_names = set(
                                    [
                                        provide["name"]
                                        for provide in result_tree[pv][ps][cn][nvr]["provides"]
                                    ]
                                )
                                for provide_name in provides_component_names:
                                    versions = set(
                                        [
                                            provide["version"]
                                            for provide in result_tree[pv][ps][cn][nvr]["provides"]
                                            if provide["name"] == provide_name
                                        ]
                                    )
                                    types = set(
                                        [
                                            provide["type"]
                                            for provide in result_tree[pv][ps][cn][nvr]["provides"]
                                            if provide["name"] == provide_name
                                        ]
                                    )
                                    arches = set(
                                        [
                                            provide["arch"]
                                            for provide in result_tree[pv][ps][cn][nvr]["provides"]
                                            if provide["name"] == provide_name
                                        ]
                                    )
                                    provides_components.append(
                                        f"{provide_name} {(','.join(versions))} ({(',').join(types)}:{','.join(arches)})"  # noqa
                                    )
                            if result_tree[pv][ps][cn][nvr]["upstreams"]:
                                upstream_component_names = sorted(
                                    list(
                                        set(
                                            [
                                                f"{upstream['nvr']} ({upstream['type']}:{upstream['arch']})"  # noqa
                                                for upstream in result_tree[pv][ps][cn][nvr][
                                                    "upstreams"
                                                ]
                                            ]
                                        )
                                    )
                                )
                                if len(upstream_component_names) > 0:
                                    upstream_component_name = upstream_component_names[0]
                                    if len(upstream_component_names) > 1:
                                        upstream_component_name = f"{upstream_component_names[0]} and {len(upstream_component_names) - 1} more"  # noqa
                                    console.print(
                                        Text(ps, style=f"{product_color} b"),
                                        f"[pale_turquoise1]{upstream_component_name}[/pale_turquoise1]",  # noqa
                                        f"[{dep}]",
                                        f"[grey]{related_url}[/grey]",
                                        no_wrap=no_wrap,
                                    )
                            if result_tree[pv][ps][cn][nvr]["sources"]:
                                source_component_names = sorted(
                                    list(
                                        set(
                                            [
                                                f"{source['nvr']} ({source['type']}:{source['arch']})"  # noqa
                                                for source in result_tree[pv][ps][cn][nvr][
                                                    "sources"
                                                ]
                                            ]
                                        )
                                    )
                                )
                                if len(source_component_names) > 0:
                                    source_component_name = source_component_names[0]
                                    if len(source_component_names) > 1:
                                        source_component_name = f"{source_component_names[0]} and {len(source_component_names) - 1} more"  # noqa
                                    console.print(
                                        Text(ps, style=f"{product_color} b"),
                                        f"[pale_turquoise1]{source_component_name}[/pale_turquoise1]",  # noqa
                                        f"[{dep}]",
                                        f"[grey]{related_url}[/grey]",
                                        no_wrap=no_wrap,
                                    )
                            if not (result_tree[pv][ps][cn][nvr]["upstreams"]) and not (
                                result_tree[pv][ps][cn][nvr]["sources"]
                            ):
                                child_dep_names = ""
                                if provides_components:
                                    try:
                                        child_dep_names = highlight_search_term(
                                            search_component_name,
                                            ", ".join(provides_components),
                                        )
                                        child_dep_names = f"[{child_dep_names}]"
                                    except re.error:
                                        pass

                                console.print(
                                    Text(ps, style=f"{product_color} b"),
                                    dep,
                                    child_dep_names,
                                    f"[i][grey]{related_url}[/grey][/i]",
                                    f"[i][grey]{build_source_url}[/grey][/i]",
                                    width=10000,
                                    no_wrap=no_wrap,
                                )

            # TODO: this is a hack how to fallback to level 3 verbosity
            # when using middleware CLI which does not have PURL stuff,
            # delete once we stop using middleware CLI completely
            middleware_cli_purl_verbose_level = (
                ctx.obj["VERBOSE"] > 3
                and ctx.obj["MIDDLEWARE_CLI"]
                and not ctx.params["no_middleware"]
            )

            if (
                ctx.obj["VERBOSE"] == 3 or middleware_cli_purl_verbose_level
            ):  # product_stream X root component nvr (type:arch) x child components [ nvr (type:arch)] x related_url x build_source_url # noqa
                for pv in result_tree.keys():
                    for ps in result_tree[pv].keys():
                        for cn in sorted(result_tree[pv][ps].keys()):
                            # select the latest nvr (from sorted list)
                            nvr = list(result_tree[pv][ps][cn].keys())[-1]
                            product_color = process_product_color(
                                result_tree[pv][ps][cn][nvr]["product_stream_relations"],
                                result_tree[pv][ps][cn][nvr]["build_type"],
                            )
                            root_component_color = process_component_color(
                                result_tree[pv][ps][cn][nvr]["namespace"],
                                result_tree[pv][ps][cn][nvr]["build_type"],
                            )
                            # highlight search term
                            dep_name = nvr
                            try:
                                dep_name = highlight_search_term(
                                    search_component_name,
                                    dep_name,
                                )
                            except re.error:
                                pass
                            dep = f"[{root_component_color}]{dep_name} ({result_tree[pv][ps][cn][nvr]['type']}:{result_tree[pv][ps][cn][nvr]['arch']})[/{root_component_color}]"  # noqa
                            related_url = result_tree[pv][ps][cn][nvr].get("related_url")
                            try:
                                if result_tree[pv][ps][cn][nvr]["related_url"]:
                                    related_url = highlight_search_term(
                                        search_component_name,
                                        result_tree[pv][ps][cn][nvr]["related_url"],
                                    )
                            except re.error:
                                pass
                            build_source_url = ""
                            if result_tree[pv][ps][cn][nvr]["build_source_url"]:
                                build_source_url = result_tree[pv][ps][cn][nvr]["build_source_url"]
                            provides_components = []
                            if "provides" in result_tree[pv][ps][cn][nvr]:
                                for provide in result_tree[pv][ps][cn][nvr]["provides"]:
                                    provides_components.append(
                                        f"{provide['nvr']} ({provide['type']}:{provide['arch']})"  # noqa
                                    )
                            if result_tree[pv][ps][cn][nvr]["upstreams"]:
                                upstream_component_names = sorted(
                                    list(
                                        set(
                                            [
                                                f"{upstream['nvr']} ({upstream['type']}:{upstream['arch']})"  # noqa
                                                for upstream in result_tree[pv][ps][cn][nvr][
                                                    "upstreams"
                                                ]
                                            ]
                                        )
                                    )
                                )
                                if len(upstream_component_names) > 0:
                                    upstream_component_name = upstream_component_names[0]
                                    if len(upstream_component_names) > 1:
                                        upstream_component_name = f"{upstream_component_names[0]} and {len(upstream_component_names) - 1} more"  # noqa
                                    console.print(
                                        Text(ps, style=f"{product_color} b"),
                                        f"[pale_turquoise1]{upstream_component_name}[/pale_turquoise1]",  # noqa
                                        f"[{dep}]",
                                        f"[grey]{related_url}[/grey]",
                                        no_wrap=no_wrap,
                                    )
                            if result_tree[pv][ps][cn][nvr]["sources"]:
                                source_component_names = sorted(
                                    list(
                                        set(
                                            [
                                                f"{source['nvr']} ({source['type']}:{source['arch']})"  # noqa
                                                for source in result_tree[pv][ps][cn][nvr][
                                                    "sources"
                                                ]
                                            ]
                                        )
                                    )
                                )
                                if len(source_component_names) > 0:
                                    source_component_name = source_component_names[0]
                                    if len(source_component_names) > 1:
                                        source_component_name = f"{source_component_names[0]} and {len(source_component_names) - 1} more"  # noqa
                                    console.print(
                                        Text(ps, style=f"{product_color} b"),
                                        f"[pale_turquoise1]{source_component_name}[/pale_turquoise1]",  # noqa
                                        f"[{dep}]",
                                        f"[grey]{related_url}[/grey]",
                                        no_wrap=no_wrap,
                                    )
                            if not (result_tree[pv][ps][cn][nvr]["upstreams"]) and not (
                                result_tree[pv][ps][cn][nvr]["sources"]
                            ):
                                child_dep_names = ""
                                if provides_components:
                                    try:
                                        child_dep_names = highlight_search_term(
                                            search_component_name,
                                            ", ".join(provides_components),
                                        )
                                        child_dep_names = f"[{child_dep_names}]"
                                    except re.error:
                                        pass

                                console.print(
                                    Text(ps, style=f"{product_color} b"),
                                    dep,
                                    child_dep_names,
                                    f"[i][grey]{related_url}[/grey][/i]",
                                    f"[i][grey]{build_source_url}[/grey][/i]",
                                    width=10000,
                                    no_wrap=no_wrap,
                                )
            if (
                ctx.obj["VERBOSE"] > 3 and not middleware_cli_purl_verbose_level
            ):  # product_stream X root component purl x child components [ purl ] x related_url x build_source_url # noqa
                for pv in result_tree.keys():
                    for ps in result_tree[pv].keys():
                        for cn in sorted(result_tree[pv][ps].keys()):
                            # select the latest nvr (from sorted list)
                            nvr = list(result_tree[pv][ps][cn].keys())[-1]
                            product_color = process_product_color(
                                result_tree[pv][ps][cn][nvr]["product_stream_relations"],
                                result_tree[pv][ps][cn][nvr]["build_type"],
                            )
                            root_component_color = process_component_color(
                                result_tree[pv][ps][cn][nvr]["namespace"],
                                result_tree[pv][ps][cn][nvr]["build_type"],
                            )
                            # highlight search term
                            dep_name = result_tree[pv][ps][cn][nvr]["purl"]
                            try:
                                dep_name = highlight_search_term(
                                    search_component_name,
                                    dep_name,
                                )
                            except re.error:
                                pass
                            dep = f"[{root_component_color}]{dep_name}[/{root_component_color}]"  # noqa
                            related_url = result_tree[pv][ps][cn][nvr].get("related_url")
                            try:
                                if result_tree[pv][ps][cn][nvr]["related_url"]:
                                    related_url = highlight_search_term(
                                        search_component_name,
                                        result_tree[pv][ps][cn][nvr]["related_url"],
                                    )
                            except re.error:
                                pass
                            build_source_url = ""
                            if result_tree[pv][ps][cn][nvr]["build_source_url"]:
                                build_source_url = result_tree[pv][ps][cn][nvr]["build_source_url"]
                            provides_components = []
                            if "provides" in result_tree[pv][ps][cn][nvr]:
                                for provide in result_tree[pv][ps][cn][nvr]["provides"]:
                                    provides_components.append(f"{provide['purl']}")
                            if result_tree[pv][ps][cn][nvr]["upstreams"]:
                                upstream_component_names = sorted(
                                    list(
                                        set(
                                            [
                                                upstream["purl"]
                                                for upstream in result_tree[pv][ps][cn][nvr][
                                                    "upstreams"
                                                ]
                                            ]
                                        )
                                    )
                                )
                                if len(upstream_component_names) > 0:
                                    upstream_component_name = upstream_component_names[0]
                                    if len(upstream_component_names) > 1:
                                        upstream_component_name = f"{upstream_component_names[0]} and {len(upstream_component_names) - 1} more"  # noqa
                                    console.print(
                                        Text(ps, style=f"{product_color} b u"),
                                        f"[pale_turquoise1]{upstream_component_name}[/pale_turquoise1]",  # noqa
                                        f"[{dep}]",
                                        f"[grey]{related_url}[/grey]",
                                        f"[grey]{build_source_url}[/grey]",
                                        no_wrap=no_wrap,
                                    )
                            if result_tree[pv][ps][cn][nvr]["sources"]:
                                source_component_names = sorted(
                                    list(
                                        set(
                                            [
                                                source["purl"]
                                                for source in result_tree[pv][ps][cn][nvr][
                                                    "sources"
                                                ]
                                            ]
                                        )
                                    )
                                )
                                if len(source_component_names) > 0:
                                    source_component_name = source_component_names[0]
                                    if len(source_component_names) > 1:
                                        source_component_name = f"{source_component_names[0]} and {len(source_component_names) - 1} more"  # noqa
                                    console.print(
                                        Text(ps, style=f"{product_color} b u"),
                                        f"[pale_turquoise1]{source_component_name}[/pale_turquoise1]",  # noqa
                                        f"[{dep}]",
                                        f"[grey]{related_url}[/grey]",
                                        f"[grey]{build_source_url}[/grey]",
                                        no_wrap=no_wrap,
                                    )
                            if not (result_tree[pv][ps][cn][nvr]["upstreams"]) and not (
                                result_tree[pv][ps][cn][nvr]["sources"]
                            ):
                                child_dep_names = ""
                                if provides_components:
                                    try:
                                        child_dep_names = highlight_search_term(
                                            search_component_name,
                                            ", ".join(provides_components),
                                        )
                                        child_dep_names = f"[{child_dep_names}]"
                                    except re.error:
                                        pass

                                console.print(
                                    Text(ps, style=f"{product_color} b"),
                                    dep,
                                    child_dep_names,
                                    f"[i][grey]{related_url}[/grey][/i]",
                                    f"[i][grey]{build_source_url}[/grey][/i]",
                                    width=10000,
                                    no_wrap=no_wrap,
                                )

        ctx.exit()


def text_output_components_contain_component(
    ctx, output, format, exclude_components, no_wrap=False
):
    if "results" in output:
        for item in output["results"]:
            component_name = item["name"]
            component_nvr = item["nvr"]
            related_url = item["related_url"]
            download_url = item["download_url"]
            arch = item["arch"]
            if not any([re.search(match, component_name) for match in exclude_components]):
                if ctx.obj["VERBOSE"] == 0:
                    ordered_sources = sorted(item["sources"], key=lambda d: d["purl"])
                    for source in ordered_sources:
                        if "arch=noarch" in source["purl"] or "arch=src" in source["purl"]:
                            source_purl = PackageURL.from_string(source["purl"])
                            root_component = source_purl.name
                            if source_purl.type == "oci" and "-source" not in source_purl.name:
                                root_component = (
                                    f"[u magenta]{source_purl.name}-container[/u magenta]"
                                )
                            if source_purl.type == "oci":
                                component_ns = Text("REDHAT", style="bold magenta")
                            elif not source_purl.namespace:
                                component_ns = Text("UPSTREAM", style="bold magenta")
                            else:
                                component_ns = Text(source_purl.namespace.upper(), style="bold red")

                            console.print(
                                component_ns,
                                source_purl.type.upper(),
                                root_component,
                                Text(component_name, style="bold white"),
                                no_wrap=no_wrap,
                            )
                if ctx.obj["VERBOSE"] == 1:
                    ordered_sources = sorted(item["sources"], key=lambda d: d["purl"])
                    for source in ordered_sources:
                        if "arch=noarch" in source["purl"] or "arch=src" in source["purl"]:
                            source_purl = PackageURL.from_string(source["purl"])
                            root_component = f"{source_purl.name}-{source_purl.version}"
                            if source_purl.type == "oci" and "-source" not in source_purl.name:
                                root_component = (
                                    f"[u magenta]{source_purl.name}-container[/u magenta]"
                                )
                            if source_purl.type == "oci":
                                component_ns = Text("REDHAT", style="bold magenta")
                            elif not source_purl.namespace:
                                component_ns = Text("UPSTREAM", style="bold magenta")
                            else:
                                component_ns = Text(source_purl.namespace.upper(), style="bold red")
                            console.print(
                                component_ns,
                                source_purl.type.upper(),
                                root_component,
                                Text(component_nvr, style="bold white"),
                                arch,
                                no_wrap=no_wrap,
                            )
                if ctx.obj["VERBOSE"] > 1:
                    ordered_sources = sorted(item["sources"], key=lambda d: d["purl"])
                    for source in ordered_sources:
                        if "arch=noarch" in source["purl"] or "arch=src" in source["purl"]:
                            source_purl = PackageURL.from_string(source["purl"])
                            root_component = f"{source_purl.name}-{source_purl.version}"
                            if source_purl.type == "oci" and "-source" not in source_purl.name:
                                root_component = (
                                    f"[u magenta]{source_purl.name}-container[/u magenta]"
                                )
                            if source_purl.type == "oci":
                                component_ns = Text("REDHAT", style="bold magenta")
                            elif not source_purl.namespace:
                                component_ns = Text("UPSTREAM", style="bold magenta")
                            else:
                                component_ns = Text(source_purl.namespace.upper(), style="bold red")
                            console.print(
                                component_ns,
                                source_purl.type.upper(),
                                root_component,
                                Text(component_nvr, style="bold white"),
                                arch,
                                related_url,
                                download_url,
                                no_wrap=no_wrap,
                            )
    ctx.exit()


def text_output_components_affected_by_cve(ctx, output, format, no_wrap=False):
    console.print("Flaw Title:", output["title"])
    console.print(
        "affects:",
    )
    for component in output["components"]:
        affected_component1 = f"({component['purl']})"
        if not ctx.obj["SHOW_PURL"]:
            purl = PackageURL.from_string(component["purl"])
            ns = "UPSTREAM"
            if purl.namespace:
                ns = purl.namespace.upper()
            affected_component = f"([bold cyan]{ns}[/bold cyan] {purl.name}-{purl.version},{purl.type.upper()})"  # noqa
            versions = [pv["name"] for pv in component["product_versions"]]
            if ctx.obj["VERBOSE"] == 0:
                console.print(
                    Text(str(versions), style="bold magenta u"),
                    ns,
                    affected_component,
                    no_wrap=no_wrap,
                )
            if ctx.obj["VERBOSE"] == 1:
                for ps in component["product_streams"]:
                    console.print(
                        Text(ps.get("name"), style="bold magenta u"),
                        ns,
                        affected_component1,
                        no_wrap=no_wrap,
                    )
            if ctx.obj["VERBOSE"] > 1:
                for ps in component["product_streams"]:
                    console.print(
                        Text(ps.get("name"), style="bold magenta u"),
                        ns,
                        affected_component1,
                        Text(component.get("build_source_url", ""), style="i"),
                        Text(component.get("related_url", ""), style="i"),
                        Text(component.get("download_url", ""), style="i"),
                        no_wrap=no_wrap,
                    )
    ctx.exit()


def text_output_products_affected_by_cve(ctx, output, format, exclude_products, no_wrap=False):
    console.print("[white]link:[/white]", output["link"])
    console.print("[white]cve_id:[/white]", output["cve_id"])
    console.print("[white]title:[/white]", output["title"])
    if ctx.obj["VERBOSE"] == 0:
        console.print(
            "[white]product_versions:[/white]",
        )
        ordered_product_versions = sorted(output["product_versions"])
        for product_version in ordered_product_versions:
            console.print(Text(product_version, style="bold magenta u"), no_wrap=no_wrap)
    if ctx.obj["VERBOSE"] > 0:
        console.print(
            "[white]product_streams:[/white]",
        )
        ordered_product_streams = sorted(output["product_streams"])
        for product_stream in ordered_product_streams:
            console.print(Text(product_stream, style="bold magenta u"), no_wrap=True)
    ctx.exit()


def text_output_get_manifest(ctx, output, format, no_wrap=False):
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
                console.print(ns, component, no_wrap=no_wrap)  # noqa
    else:
        for component in output["packages"]:
            purl = component["externalRefs"][0]["referenceLocator"]
            console.print(purl, no_wrap=no_wrap)  # noqa

    ctx.exit()


def text_output_component_flaws(ctx, output, format, no_wrap=False):
    ordered_components = sorted(output["results"], key=lambda d: d["name"])
    for item in ordered_components:
        component_name = item["name"]
        ordered_affects = sorted(
            item["affects"], key=lambda d: (d["flaw_cve_id"] is None, d["flaw_cve_id"])
        )
        for affect in ordered_affects:
            flaw_cve_id = "Vulnerability"
            if affect["flaw_cve_id"]:
                flaw_cve_id = affect["flaw_cve_id"]
            if ctx.obj["VERBOSE"] == 0:
                console.print(
                    Text(flaw_cve_id, style="magenta"),
                    Text(component_name, style="white"),
                    Text(affect["affect_product_version"], style="cyan"),
                    affect["affect_affectedness"],
                    affect["affect_impact"],
                    affect["affect_resolution"],
                    no_wrap=no_wrap,
                )
            if ctx.obj["VERBOSE"] == 1:
                console.print(
                    Text(flaw_cve_id, style="magenta"),
                    Text(component_name, style="white"),
                    Text(affect["affect_product_version"], style="cyan"),
                    f"(state: {affect['flaw_state']} resolution:{affect['flaw_resolution']})",
                    affect["affect_affectedness"],
                    affect["affect_impact"],
                    affect["affect_resolution"],
                    no_wrap=no_wrap,
                )
            if ctx.obj["VERBOSE"] > 1:
                console.print(Text(affect["title"], style="white"))
                console.print(
                    Text(component_name, style="magenta"),
                    Text(affect["affect_product_version"], style="cyan"),
                    f"(state: {affect['flaw_state']} resolution:{affect['flaw_resolution']})",
                    affect["affect_affectedness"],
                    affect["affect_impact"],
                    affect["affect_resolution"],
                    no_wrap=True,
                )
    ctx.exit()


def text_output_product_flaws(ctx, output, format, no_wrap=False):
    for item in output["results"]:
        component_name = item["name"]
        for affect in item["affects"]:
            flaw_cve_id = "Vulnerability"
            if affect["flaw_cve_id"]:
                flaw_cve_id = affect["flaw_cve_id"]
            if ctx.obj["VERBOSE"] == 0:
                console.print(
                    Text(flaw_cve_id, style="magenta"),
                    Text(component_name, style="white"),
                    affect["affect_component_name"],
                    affect["affect_affectedness"],
                    affect["affect_impact"],
                    affect["affect_resolution"],
                    no_wrap=no_wrap,
                )
            if ctx.obj["VERBOSE"] == 1:
                console.print(
                    Text(flaw_cve_id, style="magenta"),
                    Text(component_name, style="white"),
                    f"(state: {affect['flaw_state']} resolution:{affect['flaw_resolution']})",
                    affect["affect_component_name"],
                    affect["affect_affectedness"],
                    affect["affect_impact"],
                    affect["affect_resolution"],
                    no_wrap=no_wrap,
                )
            if ctx.obj["VERBOSE"] > 1:
                console.print(affect["title"])
                console.print(
                    Text(flaw_cve_id, style="magenta"),
                    Text(component_name, style="white"),
                    f"(state: {affect['flaw_state']} resolution:{affect['flaw_resolution']})",
                    affect["affect_component_name"],
                    affect["affect_affectedness"],
                    affect["affect_impact"],
                    affect["affect_resolution"],
                    no_wrap=no_wrap,
                )
    ctx.exit()


def text_output_list(ctx, output, format, exclude_components, no_wrap=False):
    if "results" in output and output["count"] > 0:
        # handle component
        if "purl" in output["results"][0]:
            ordered_components = sorted(output["results"], key=lambda d: d["name"])
            for row in ordered_components:
                if not any([re.search(match, row["purl"]) for match in exclude_components]):
                    if "purl" in row:
                        purl = PackageURL.from_string(row["purl"])
                        if purl.type == "oci":
                            component_ns = Text("REDHAT", style="bold magenta")
                        elif not purl.namespace:
                            component_ns = Text("UPSTREAM", style="bold magenta")
                        else:
                            component_ns = Text(purl.namespace.upper(), style="bold red")

                        sha256 = ""
                        if purl.version:
                            if purl.version.startswith("sha256"):
                                sha256 = output_version(ctx, purl.version)
                        nvr = None
                        if "nvr" in row:
                            nvr = row["nvr"]

                        if not ctx.obj["SHOW_PURL"]:
                            if ctx.obj["VERBOSE"] == 0:
                                console.print(
                                    component_ns,
                                    purl.type.upper(),
                                    Text(nvr, style="bold white"),
                                    sha256,
                                    row["related_url"],
                                    purl.qualifiers.get("arch"),
                                )
                            if ctx.obj["VERBOSE"] > 0:
                                download_url = ""
                                if "download_url" in row:
                                    download_url = row["download_url"]
                                console.print(
                                    component_ns,
                                    purl.type.upper(),
                                    Text(nvr, style="bold white"),
                                    sha256,
                                    row["related_url"],
                                    purl.qualifiers.get("arch"),
                                    download_url,
                                )
                        else:
                            console.print(
                                row["purl"],
                            )
        # handle flaw
        if "cve_id" in output["results"][0]:
            for row in output["results"]:
                console.print(
                    row["cve_id"],
                    row["title"],
                    row["state"],
                    row["impact"],
                    row["resolution"],
                    no_wrap=no_wrap,
                )

        # handle trackers
        if all(key in output["results"][0] for key in ("external_system_id", "status")):
            for row in output["results"]:
                console.print(
                    row["external_system_id"],
                    row["type"],
                    row["status"],
                    no_wrap=no_wrap,
                )

        # handle products
        if "ofuri" in output["results"][0]:
            for row in output["results"]:
                console.print(
                    Text(row["name"], style="magenta bold u"),
                    row["ofuri"],
                    no_wrap=no_wrap,
                )
        # handle channels
        if "relative_url" in output["results"][0]:
            for row in output["results"]:
                console.print(
                    Text(row["name"], style="magenta bold u"),
                    row["type"],
                    row["description"],
                    no_wrap=no_wrap,
                )
        # handle builds
        if "build_id" in output["results"][0]:
            for row in output["results"]:
                console.print(
                    Text(str(row["build_id"]), style="magenta bold u"),
                    row["build_type"],
                    Text(row["name"], style="white"),
                    row["created_at"],
                    Text(row["link"], style="i"),
                    no_wrap=no_wrap,
                )

    ctx.exit()


def text_output_purls(ctx, output, format, no_wrap=False):
    if "results" in output and output["count"] > 0:
        # handle component
        if "purl" in output["results"][0]:
            ordered_components = sorted(output["results"], key=lambda d: d["purl"])
            for row in ordered_components:
                if "purl" in row:
                    purl = PackageURL.from_string(row["purl"])
                    if not purl.namespace:
                        component_ns = Text("UPSTREAM", style="bold magenta")
                    else:
                        component_ns = Text(purl.namespace.upper(), style="bold red")
                    if ctx.obj["VERBOSE"] == 0:
                        console.print(
                            component_ns,
                            purl.type.upper(),
                            Text(purl.name, style="bold white"),
                            purl.version,
                            purl.qualifiers.get("arch"),
                            no_wrap=no_wrap,
                        )
                    if ctx.obj["VERBOSE"] > 0:
                        console.print(
                            component_ns,
                            purl.type.upper(),
                            Text(purl.name, style="bold white"),
                            purl.version,
                            purl.qualifiers.get("arch"),
                            row["link"],
                            no_wrap=no_wrap,
                        )
        ctx.exit()


def text_output_generic(ctx, output, format, no_wrap=False):
    for k, v in output.items():
        key_name = Text(k)
        key_name.stylize("bold magenta")
        console.print(key_name, " : ", v, no_wrap=no_wrap)


def cprint(
    data,
    dest=DEST.CONSOLE,
    filename=None,
    ctx=None,
    show_count: bool = True,
):
    """handle format and output"""
    from griffon import get_config_option

    exclude_products = []
    if get_config_option(ctx.obj["PROFILE"], "exclude"):
        exclude_products = get_config_option(ctx.obj["PROFILE"], "exclude").split("\n")
    logger.debug(f"exclude products = {exclude_products}")

    exclude_components = []
    if get_config_option(ctx.obj["PROFILE"], "exclude_components"):
        exclude_components = get_config_option(ctx.obj["PROFILE"], "exclude_components").split("\n")
    logger.debug(f"exclude_components = {exclude_components}")

    output = raw_json_transform(data, show_count)
    if ctx and ctx.obj["NO_COLOR"]:
        console.no_color = True
    format = OUTPUT_FORMAT.JSON
    if ctx and "FORMAT" in ctx.obj:
        format = OUTPUT_FORMAT(ctx.obj["FORMAT"])
    if format is OUTPUT_FORMAT.TEXT:
        no_wrap = ctx.obj["NO_WRAP"]
        terminal_width = ctx.obj["TERMINAL_WIDTH"]
        console.width = int(terminal_width)
        if ctx.info_name == "product-summary":
            text_output_product_summary(ctx, output, format, exclude_products, no_wrap=no_wrap)
        if ctx.info_name == "products-contain-component":
            text_output_products_contain_component(
                ctx,
                output,
                exclude_products,
                exclude_components,
                no_wrap=no_wrap,
            )
        if ctx.info_name == "components-contain-component":
            text_output_components_contain_component(
                ctx, output, format, exclude_components, no_wrap=no_wrap
            )
        if ctx.info_name == "components-affected-by-flaw":
            text_output_components_affected_by_cve(ctx, output, format, no_wrap=no_wrap)
        if ctx.info_name == "products-affected-by-flaw":
            text_output_products_affected_by_cve(
                ctx, output, format, exclude_products, no_wrap=no_wrap
            )
        if ctx.info_name == "get-manifest":
            text_output_get_manifest(ctx, output, format, no_wrap=no_wrap)
        if ctx.info_name == "list":
            text_output_list(ctx, output, format, exclude_components, no_wrap=no_wrap)
        if ctx.info_name == "component-flaws":
            text_output_component_flaws(ctx, output, format, no_wrap=no_wrap)
        if ctx.info_name == "product-flaws":
            text_output_product_flaws(ctx, output, format, no_wrap=no_wrap)
        if ctx.info_name == "provides":
            text_output_purls(ctx, output, format, no_wrap=no_wrap)
        if ctx.info_name == "sources":
            text_output_purls(ctx, output, format, no_wrap=no_wrap)
        if ctx.info_name == "tree":
            text_output_tree(ctx, output, no_wrap=no_wrap)

        # last chance text formatted output
        text_output_generic(ctx, output, format, no_wrap=no_wrap)

    if format is OUTPUT_FORMAT.JSON:
        if dest is DEST.CONSOLE:
            console.print_json(json.dumps(output))

    # if we instructed to open browser, open that up now
    if ctx:
        if "link" in data and "open_browser" in ctx.obj:
            if ctx.obj["open_browser"]:
                click.launch(data["link"])

    exit(0)
