"""

"""
import copy
import logging

import click
from component_registry_bindings.bindings.python_client.api.v1 import v1_components_list
from component_registry_bindings.bindings.python_client.models import Component

from griffon import CorgiService, OSIDBService, progress_bar
from griffon.autocomplete import (
    get_component_names,
    get_cve_ids,
    get_product_stream_names,
    get_product_stream_ofuris,
    get_product_version_names,
)
from griffon.commands.entities.corgi import (
    get_component_manifest,
    get_component_summary,
    get_product_stream_manifest,
    list_components,
)
from griffon.commands.entities.helpers import query_params_options
from griffon.commands.reports import (
    generate_affects_report,
    generate_entity_report,
    generate_license_report,
)
from griffon.output import console, cprint, raw_json_transform
from griffon.services import QueryService, core_queries  # , exp

logger = logging.getLogger("griffon")

query_service = QueryService()


@click.group(name="service", help="Service operations.")
@click.pass_context
def queries_grp(ctx):
    """Query operations."""
    pass


queries_grp.add_command(generate_affects_report)
queries_grp.add_command(generate_entity_report)
queries_grp.add_command(generate_license_report)

# queries_grp.add_command(generate_affects_for_component_process)


@queries_grp.command(
    name="product-summary",
    help="Get Product summaries.",
)
@click.argument(
    "product_stream_name",
    required=False,
    type=click.STRING,
    shell_complete=get_product_stream_names,
)
# TODO - underlying bindings need to support 'ofuri'
# @click.option(
#     "--ofuri",
#     "ofuri",
#     type=click.STRING,
#     shell_complete=get_product_stream_ofuris,
#     help="UNDER DEVELOPMENT",
# )
@click.option(
    "-s",
    "strict_name_search",
    is_flag=True,
    default=False,
    help="Strict search, exact match of name.",
)
@click.option(
    "--all",
    "all",
    is_flag=True,
    default=False,
    help="Return all Products.",
)
@click.pass_context
@progress_bar
def get_product_summary(ctx, product_stream_name, strict_name_search, all):
    """get product stream."""
    if not product_stream_name and not all and not strict_name_search:
        click.echo(ctx.get_help())
        exit(0)
    q = query_service.invoke(core_queries.product_stream_summary, ctx.params)
    cprint(q, ctx=ctx)


@queries_grp.command(
    name="component-summary",
    help="Get Component summaries.",
)
@click.argument(
    "component_name",
    required=False,
    type=click.STRING,
    shell_complete=get_component_names,
)
@click.option(
    "-s",
    "strict_name_search",
    is_flag=True,
    default=False,
    help="Strict search, exact match of name.",
)
@click.pass_context
def retrieve_component_summary(ctx, component_name, strict_name_search):
    """Get Component summary."""
    if not component_name:
        click.echo(ctx.get_help())
        exit(0)
    cond = {}
    if component_name:
        cond["component_name"] = component_name
    ctx.invoke(get_component_summary, **cond)


@queries_grp.command(
    name="products-contain-component",
    help="List Products containing Component.",
)
@click.argument(
    "component_name",
    required=False,
)
@click.option(
    "--purl", help="Component purl, needs to be in quotes (ex. 'pkg:rpm/python-pyjwt@1.7.1')"
)
@click.option(
    "--arch",
    default="src",
    type=click.Choice(CorgiService.get_component_arches()),
)
@click.option(
    "--namespace", default=None, type=click.Choice(CorgiService.get_component_namespaces())
)
@click.option("--type", "component_type", type=click.Choice(CorgiService.get_component_types()))
@click.option(
    "-s",
    "strict_name_search",
    is_flag=True,
    default=False,
    help="Strict search, exact match of component name.",
)
@click.option(
    "--generate-affects",
    "-a",
    "affect_mode",
    is_flag=True,
    default=False,
    help="Generate Affects output.",
)
# @click.option(
#     "--cve-id",
#     "cve_id",
#     help="Attach affects to this (\033[1mCVE-ID\033[0m).",
# )
@click.option(
    "--sfm2-flaw-id",
    "sfm2_flaw_id",
    help="Attach affects to this (\033[1msfm2 flaw id\033[0m).",
)
@click.option(
    "--flaw-mode",
    "flaw_mode",
    default="dry_run",
    type=click.Choice(["add", "replace", "dry_run"]),
    help="Add or update when generating affects.",
)
@click.option(
    "--search-latest",
    "search_latest",
    is_flag=True,
    default=False,
    help="Search root Components (\033[1menabled by default\033[0m).",
)
@click.option(
    "--search-related-url",
    "search_related_url",
    is_flag=True,
    default=False,
    help="Search related url (\033[1menabled by default\033[0m).",
)
@click.option(
    "--filter-rh-naming",
    is_flag=True,
    default=False,
    help="Filter rh naming (\033[1menabled by default\033[0m).",
)
@click.option(
    "--search-all",
    "search_all",
    is_flag=True,
    default=False,
    help="Search root Components and dependencies.",
)
@click.option(
    "--search-community",
    "search_community",
    is_flag=True,
    default=False,
    help="Search community Components (\033[1mNot Implemented\033[0m).",
)
@click.option(
    "--search-upstreams",
    "search_upstreams",
    is_flag=True,
    default=False,
    help="Search for Components by upstream.",
)
@click.pass_context
def get_product_contain_component(
    ctx,
    component_name,
    purl,
    arch,
    namespace,
    component_type,
    strict_name_search,
    affect_mode,
    sfm2_flaw_id,
    flaw_mode,
    search_latest,
    search_related_url,
    filter_rh_naming,
    search_all,
    search_community,
    search_upstreams,
):
    with console.status("griffoning", spinner="line") as operation_status:
        """List products of a latest component."""
        if not purl and not component_name:
            click.echo(ctx.get_help())
            click.echo("")
            click.echo("\033[1mMust supply Component name or --purl.\033[0m")
            exit(0)

        if (
            not search_latest
            and not search_all
            and not search_related_url
            and not search_community
            and not search_upstreams
        ):
            ctx.params["search_latest"] = True
            ctx.params["search_related_url"] = True
            # ctx.params["filter_rh_naming"] = True

        params = copy.deepcopy(ctx.params)
        params.pop("sfm2_flaw_id")
        params.pop("flaw_mode")
        params.pop("affect_mode")
        if component_name:
            q = query_service.invoke(core_queries.products_containing_component_query, params)
        if purl:
            q = query_service.invoke(
                core_queries.products_containing_specific_component_query, params
            )

        # TODO - in the short term affect handling will be mediated via sfm2 here in the operation itself # noqa
        if ctx.params["sfm2_flaw_id"]:
            console.no_color = True
            console.highlighter = None
            operation_status.stop()

            # generate affects
            output = raw_json_transform(q, True)
            ordered_results = sorted(output["results"], key=lambda d: d["product_stream"])
            affects = []
            product_versions = sorted(
                list(set([item["product_version"] for item in ordered_results]))
            )
            for pv in product_versions:
                names = [item["name"] for item in ordered_results if pv == item["product_version"]]
                names = list(set(names))
                for name in names:
                    affects.append(
                        {"product_version": pv, "component_name": name, "operation": "add"}
                    )

            # attempt to import sfm2client module
            try:
                import sfm2client
            except ImportError:
                logger.warning("sfm2client library not found, cannot compare with flaw affects")
                ctx.exit()

            # TODO: paramaterise into dotfile/env var
            sfm2 = sfm2client.api.core.SFMApi({"url": "http://localhost:5600"})
            try:
                flaw = sfm2.flaw.get(sfm2_flaw_id)
            except Exception as e:
                logger.warning(f"Could not retrieve flaw {sfm2_flaw_id}: {e}")
                return

            if ctx.params["flaw_mode"] == "replace":
                if affects:
                    console.print(
                        f"The following affects will REPLACE all flaw {flaw['id']}'s existing affects in \"new\" state:\n"  # noqa
                    )
                    for m in affects:
                        console.print(
                            f"{m['product_version']}\t{m['component_name']}",
                            no_wrap=False,
                        )

                    if click.confirm(
                        f"\nREPLACE flaw {flaw['id']}'s existing affects in \"new\" state with the above? THIS CANNOT BE UNDONE: ",  # noqa
                        default=True,
                    ):
                        click.echo("Updating ...")
                        # only discard affects in 'new' state, we should preserve all others so not to throw work away # noqa
                        new_affects = [a for a in flaw["affects"] if a["affected"] != "new"]
                        # get map of existing affects first, so that we don't try to add duplicates
                        existing = set((a["ps_module"], a["ps_component"]) for a in new_affects)
                        for m in affects:
                            if (m["product_version"], m["component_name"]) in existing:
                                continue
                            new_affects.append(
                                {
                                    "affected": "new",
                                    "ps_component": m["component_name"],
                                    "ps_module": m["product_version"],
                                }
                            )
                        try:
                            sfm2.flaw.update(flaw["id"], data={"affects": new_affects})
                        except Exception as e:
                            msg = e.response.json()
                            logger.warning(f"Failed to update flaw: {e}: {msg}")
                        console.print("Operation done.")
                        ctx.exit()

                    click.echo("No affects were added to flaw.")
                else:
                    console.print("No affects to add to flaw.")
            else:
                missing = []
                for affect in affects:
                    flaw_has_affect = False
                    for a in flaw.get("affects"):
                        if a.get("ps_module") == affect.get("product_version") and a.get(
                            "ps_component"
                        ) == affect.get("component_name"):
                            flaw_has_affect = True
                    if not flaw_has_affect:
                        missing.append(affect)

                if missing:
                    console.log("Flaw is missing the following affect entries:\n")
                    for m in missing:
                        console.print(
                            f"{m['product_version']}\t{m['component_name']}",
                            no_wrap=False,
                        )
                    if click.confirm(
                        "Would you like to add them? ",
                        default=True,
                    ):
                        click.echo("Updating ...")

                        updated_affects = flaw.get("affects")[:]
                        for m in missing:
                            updated_affects.append(
                                {
                                    "affected": "new",
                                    "ps_component": m["component_name"],
                                    "ps_module": m["product_version"],
                                }
                            )
                        try:
                            sfm2.flaw.update(flaw["id"], data={"affects": updated_affects})
                        except Exception as e:
                            msg = e.response.json()
                            logger.warning(f"Failed to update flaw: {e}: {msg}")
                        console.print("Operation done.")
                        ctx.exit()
                    click.echo("No affects were added to flaw.")

                else:
                    console.print("Flaw is not missing any affect entries")

            ctx.exit()

        cprint(q, ctx=ctx)


@queries_grp.command(
    name="components-contain-component",
    help="List Components containing Component.",
)
@click.argument("component_name", required=False)
@click.option("--purl")
@click.option("--type", "component_type", type=click.Choice(CorgiService.get_component_types()))
@click.option("--version", "component_version")
@click.option(
    "--arch",
    "component_arch",
    type=click.Choice(CorgiService.get_component_arches()),
    help="Default arch=src.",
)
@click.option("--namespace", type=click.Choice(CorgiService.get_component_namespaces()))
@click.option(
    "-s",
    "strict_name_search",
    is_flag=True,
    default=False,
    help="Strict search, exact match of component name.",
)
@click.pass_context
@progress_bar
def get_component_contain_component(
    ctx,
    component_name,
    purl,
    component_type,
    component_version,
    component_arch,
    namespace,
    strict_name_search,
):
    """List components that contain component."""
    if not component_name and not purl:
        click.echo(ctx.get_help())
        exit(0)
    if component_name:
        q = query_service.invoke(core_queries.components_containing_component_query, ctx.params)
        cprint(q, ctx=ctx)
    if purl:
        q = query_service.invoke(
            core_queries.components_containing_specific_component_query, ctx.params
        )
        cprint(q, ctx=ctx)


@queries_grp.command(
    name="product-manifest",
    help="Get Product manifest (includes Root Components and all dependencies).",
)
@click.argument("product_stream_name", required=False, shell_complete=get_product_stream_names)
@click.option("--ofuri", "ofuri", type=click.STRING, shell_complete=get_product_stream_ofuris)
@click.option(
    "--spdx-json",
    "spdx_json_format",
    is_flag=True,
    default=False,
    help="Generate spdx manifest (json).",
)
@click.pass_context
def get_product_manifest_query(ctx, product_stream_name, ofuri, spdx_json_format):
    """List components of a specific product version."""
    if not ofuri and not product_stream_name:
        click.echo(ctx.get_help())
        exit(0)

    if spdx_json_format:
        ctx.ensure_object(dict)
        ctx.obj["FORMAT"] = "json"  # TODO - investigate if we need yaml format.

    cond = {}
    if ofuri:
        cond["ofuri"] = ofuri
    if product_stream_name:
        cond["product_stream_name"] = product_stream_name
    ctx.invoke(get_product_stream_manifest, **cond)


@queries_grp.command(
    name="product-components",
    help="List LATEST Root Components of Product.",
)
@click.argument("product_stream_name", required=False, shell_complete=get_product_stream_names)
@click.option("--ofuri", "ofuri", type=click.STRING, shell_complete=get_product_stream_ofuris)
@query_params_options(
    entity="Component",
    endpoint_module=v1_components_list,
    options_overrides={
        "include_fields": {"type": click.Choice(CorgiService.get_fields(Component))},
    },
)
@click.pass_context
def get_product_latest_components_query(ctx, product_stream_name, ofuri, **params):
    """List components of a specific product version."""
    if not ofuri and not product_stream_name:
        click.echo(ctx.get_help())
        exit(0)
    if ofuri:
        params["ofuri"] = ofuri
    if product_stream_name:
        # lookup ofuri
        session = CorgiService.create_session()
        ps = session.product_streams.retrieve_list(name=product_stream_name)
        params["ofuri"] = ps["ofuri"]
    ctx.invoke(list_components, **params)


@queries_grp.command(
    name="component-manifest",
    help="Get Component manifest.",
)
@click.option("--uuid", "component_uuid")
@click.option("--purl", help="Component Purl (must be quoted).")
@click.option(
    "--spdx-json",
    "spdx_json_format",
    is_flag=True,
    default=False,
    help="Generate spdx manifest (json).",
)
@click.pass_context
def retrieve_component_manifest(ctx, component_uuid, purl, spdx_json_format):
    """Retrieve Component manifest."""
    if not component_uuid and not purl:
        click.echo(ctx.get_help())
        exit(0)
    if spdx_json_format:
        ctx.ensure_object(dict)
        ctx.obj["FORMAT"] = "json"
    cond = {}
    if component_uuid:
        cond["uuid"] = component_uuid
    if purl:
        cond["purl"] = purl
    ctx.invoke(get_component_manifest, **cond)


@queries_grp.command(
    name="components-affected-by-flaw",
    help="List Components affected by Flaw.",
)
@click.argument("cve_id", required=False, type=click.STRING, shell_complete=get_cve_ids)
@click.option(
    "--affectedness",
    help="Filter by Affect affectedness.",
    type=click.Choice(OSIDBService.get_affect_affectedness()),
)
@click.option(
    "--resolution",
    "affect_resolution",
    help="Filter by Affect resolution.",
    type=click.Choice(OSIDBService.get_affect_resolution()),
)
@click.option(
    "--impact",
    "affect_impact",
    help="Filter by Affect impact.",
    type=click.Choice(OSIDBService.get_affect_impact()),
)
@click.option(
    "--type",
    "component_type",
    type=click.Choice(CorgiService.get_component_types()),
    help="Filter by Component type.",
)
@click.option(
    "--namespace",
    type=click.Choice(CorgiService.get_component_namespaces()),
    help="filter by Component namespace.",
)
@click.pass_context
@progress_bar
def components_affected_by_specific_cve_query(
    ctx, cve_id, affectedness, affect_resolution, affect_impact, component_type, namespace
):
    """List components affected by specific CVE."""
    if not cve_id:
        click.echo(ctx.get_help())
        exit(0)
    q = query_service.invoke(core_queries.components_affected_by_specific_cve_query, ctx.params)
    cprint(q, ctx=ctx)


@queries_grp.command(
    name="products-affected-by-flaw",
    help="List Products affected by Flaw.",
)
@click.argument("cve_id", required=False, type=click.STRING, shell_complete=get_cve_ids)
@click.pass_context
@progress_bar
def product_versions_affected_by_cve_query(ctx, cve_id):
    """List Products affected by a CVE."""
    if not cve_id:
        click.echo(ctx.get_help())
        exit(0)
    q = query_service.invoke(
        core_queries.products_versions_affected_by_specific_cve_query, ctx.params
    )
    cprint(q, ctx=ctx)


@queries_grp.command(name="component-flaws", help="List Flaws affecting a Component.")
@click.argument("component_name", required=False)
@click.option("--purl")
@click.option(
    "--flaw-state",
    "flaw_state",
    help="Filter by Flaw state.",
    type=click.Choice(OSIDBService.get_flaw_states()),
)
@click.option(
    "--flaw-impact",
    "flaw_impact",
    help="Filter by Flaw impact.",
    type=click.Choice(OSIDBService.get_flaw_impacts()),
)
@click.option(
    "--flaw-resolution",
    "flaw_resolution",
    help="Filter by Flaw resolution.",
    type=click.Choice(OSIDBService.get_flaw_resolutions()),
)
@click.option(
    "--affectedness",
    help="Filter by Affect affectedness.",
    type=click.Choice(OSIDBService.get_affect_affectedness()),
)
@click.option(
    "--affect-resolution",
    "affect_resolution",
    help="Filter by Affect resolution.",
    type=click.Choice(OSIDBService.get_affect_resolution()),
)
@click.option(
    "--affect-impact",
    "affect_impact",
    help="Filter by Affect impact.",
    type=click.Choice(OSIDBService.get_affect_impact()),
)
@click.option(
    "-s",
    "strict_name_search",
    is_flag=True,
    default=False,
    help="Strict search, exact match of component name.",
)
@click.pass_context
@progress_bar
def cves_for_specific_component_query(
    ctx,
    component_name,
    purl,
    flaw_state,
    flaw_impact,
    flaw_resolution,
    affectedness,
    affect_resolution,
    affect_impact,
    strict_name_search,
):
    """List flaws of a specific component."""
    if not purl and not component_name:
        click.echo(ctx.get_help())
        exit(0)

    q = query_service.invoke(core_queries.cves_for_specific_component_query, ctx.params)
    cprint(q, ctx=ctx)


@queries_grp.command(
    name="product-flaws",
    help="List Flaws affecting a Product.",
)
@click.argument(
    "product_version_name",
    required=False,
    type=click.STRING,
    shell_complete=get_product_version_names,
)
@click.option("--ofuri")
@click.option(
    "--flaw-state",
    "flaw_state",
    help="Filter by Flaw state.",
    type=click.Choice(OSIDBService.get_flaw_states()),
)
@click.option(
    "--flaw-impact",
    "flaw_impact",
    help="Filter by Flaw impact.",
    type=click.Choice(OSIDBService.get_flaw_impacts()),
)
@click.option(
    "--flaw-resolution",
    "flaw_resolution",
    help="Filter by Flaw resolution.",
    type=click.Choice(OSIDBService.get_flaw_resolutions()),
)
@click.option(
    "--affectedness",
    help="Filter by Affect affectedness.",
    type=click.Choice(OSIDBService.get_affect_affectedness()),
)
@click.option(
    "--affect-resolution",
    "affect_resolution",
    help="Filter by Affect resolution.",
    type=click.Choice(OSIDBService.get_affect_resolution()),
)
@click.option(
    "--affect-impact",
    "affect_impact",
    help="Filter by Affect impact.",
    type=click.Choice(OSIDBService.get_affect_impact()),
)
@click.option(
    "-s",
    "strict_name_search",
    is_flag=True,
    default=False,
    help="Strict search, exact match of component name.",
)
@click.pass_context
def cves_for_specific_product_query(
    ctx,
    product_version_name,
    ofuri,
    flaw_state,
    flaw_impact,
    flaw_resolution,
    affectedness,
    affect_impact,
    affect_resolution,
    strict_name_search,
):
    """List flaws of a specific product."""
    if not product_version_name and not ofuri:
        click.echo(ctx.get_help())
        exit(0)
    q = query_service.invoke(core_queries.cves_for_specific_product_query, ctx.params)
    cprint(q, ctx=ctx)
