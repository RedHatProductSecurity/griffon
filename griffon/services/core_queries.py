"""
    read only queries

"""
import concurrent
import logging
from typing import Any, Dict, List

import requests

from griffon import CORGI_API_URL, OSIDB_API_URL, CorgiService, OSIDBService

logger = logging.getLogger("rich")


class product_stream_summary:
    """retrieve product_stream summary"""

    name = "product_stream_summary"
    description = "retrieve product_stream summary"
    allowed_params = ["strict_name_search", "product_stream_name", "ofuri"]

    def __init__(self, params: dict) -> None:
        self.corgi_session = CorgiService.create_session()
        self.params = params
        self.product_stream_name = self.params.get("product_stream_name")
        self.ofuri = self.params.get("ofuri")
        self.strict_name_search = self.params.get("strict_name_search", None)

    def execute(self) -> List[Dict[str, Any]]:
        cond = {}

        if self.ofuri:
            cond["ofuri"] = self.ofuri
        elif not self.strict_name_search:
            cond["re_name"] = self.product_stream_name
        else:
            cond["name"] = self.product_stream_name

        # TODO - corgi bindings need to support ofuri in product_streams
        product_streams = self.corgi_session.product_streams.retrieve_list(
            **cond,
            limit=400,
            include_fields="link,ofuri,name,products,product_versions,brew_tags,manifest",
        )
        results = []
        if product_streams.results:
            for ps in product_streams.results:
                result = {
                    "link": ps.link,
                    "ofuri": ps.ofuri,
                    "name": ps.name,
                    "product": ps.products[0]["name"],
                    "product_version": ps.product_versions[0]["name"],
                    "brew_tags": [brew_tag for brew_tag in ps.brew_tags.to_dict().keys()],
                    "build_count": ps.build_count,
                    "manifest_link": ps.manifest,
                    "latest_components_link": ps.components,
                    "all_components_link": f"{CORGI_API_URL}/api/v1/components?product_streams={ps.ofuri}&include_fields=link,name,purl",  # noqa
                }
                results.append(result)
        else:
            result = {
                "link": product_streams["link"],
                "ofuri": product_streams["ofuri"],
                "name": product_streams["name"],
                "product": product_streams["products"][0]["name"],
                "product_version": product_streams["product_versions"][0]["name"],
                "brew_tags": "",
                "manifest_link": product_streams["manifest"],
                "all_components_link": f"{CORGI_API_URL}/api/v1/components?product_streams={product_streams['ofuri']}&include_fields=link,name,purl",  # noqa
            }
            results.append(result)
        return results


class products_versions_affected_by_specific_cve_query:
    """Given a specific CVE ID, what products are affected?"""

    name = "product-versions-affected-by-specific-cve"
    description = "Given a specific CVE ID, what product versions are affected?"
    allowed_params = ["cve_id"]

    def __init__(self, params: dict) -> None:
        self.osidb_session = OSIDBService.create_session()
        self.params = params

    def execute(self) -> dict:
        cve_id = self.params["cve_id"]
        flaw = self.osidb_session.flaws.retrieve(cve_id)
        affects = list()
        pv_names = list()
        for affect in flaw.affects:
            pv_names.append(affect.ps_module)
            affects.append(
                {"component_name": affect.ps_component, "product_version_name": affect.ps_module}
            )
        pv_names = list(set(pv_names))
        product_versions = list()
        for pv_name in pv_names:
            product_versions.append(
                {
                    "link": f"{CORGI_API_URL}/api/v1/product_versions?name={pv_name}",
                    "name": pv_name,
                }
            )
        return {
            "link": f"{OSIDB_API_URL}/osidb/api/v1/flaws/{cve_id}",
            "cve_id": cve_id,
            "title": flaw.title,
            "description": flaw.description,
            "product_versions": product_versions,
            "affects": affects,
        }


class products_containing_specific_component_query:
    """What products contain a specific component?"""

    name = "products_containing_specific_component_query"
    description = "What products contain a specific component?"
    allowed_params = [
        "component_name",
        "purl",
        "arch",
        "namespace",
        "component_type",
        "strict_name_search",
        "affect_mode",
        "search_deps",
    ]

    def __init__(self, params: dict) -> None:
        self.corgi_session = CorgiService.create_session()
        self.params = params
        self.purl = self.params.get("purl")

    def execute(self) -> dict:
        c = self.corgi_session.components.retrieve_list(
            purl=self.purl,
        )
        return c["product_streams"]


class products_containing_component_query:
    """What products contain a component?"""

    name = "products_containing_component_query"
    description = "What products contain a component?"
    allowed_params = [
        "component_name",
        "purl",
        "arch",
        "namespace",
        "component_type",
        "strict_name_search",
        "affect_mode",
        "search_deps",
    ]

    def __init__(self, params: dict) -> None:
        self.corgi_session = CorgiService.create_session()
        self.params = params
        self.component_name = self.params.get("component_name")
        self.component_type = self.params.get("component_type")
        self.strict_name_search = self.params.get("strict_name_search")
        self.search_deps = self.params.get("search_deps")
        self.ns = self.params.get("namespace")

    def execute(self) -> List[Dict[str, Any]]:
        params = {"view": "latest"}
        if not self.strict_name_search:
            params["re_name"] = self.component_name  # type: ignore
        else:
            params["name"] = self.component_name  # type: ignore
        # TODO - not yet exposed in bindings
        response = requests.get(f"{CORGI_API_URL}/api/v1/components", params=params)
        latest_src_results = response.json()["results"]
        return latest_src_results


class components_containing_specific_component_query:
    """What components contain a specific component?"""

    name = "components_containing_specific_component_query"
    description = "What components contain a specific component?"
    allowed_params = [
        "component_re_name",
        "component_name",
        "purl",
        "component_type",
        "component_version",
        "component_arch",
        "namespace",
        "strict_name_search",
    ]

    def __init__(self, params: dict):
        self.corgi_session = CorgiService.create_session()
        self.params = params
        self.purl = self.params.get("purl")

    def execute(self) -> dict:
        if self.purl:
            c = self.corgi_session.components.retrieve_list(
                purl=self.purl,
            )
            component_type = self.params["component_type"]
            sources = c["sources"]
            if component_type:
                sources = [source for source in sources if component_type.lower() in source["purl"]]
        return {
            "link": c["link"],
            "type": c["type"],
            "name": c["name"],
            "version": c["version"],
            "purl": c["purl"],
            "sources": sources,
        }


class components_containing_component_query:
    """What components contain a component?"""

    name = "components_containing_component_query"
    description = "What components contain a component?"
    allowed_params = [
        "component_name",
        "purl",
        "component_type",
        "component_version",
        "component_arch",
        "namespace",
        "strict_name_search",
    ]

    def __init__(self, params: dict) -> None:
        self.corgi_session = CorgiService.create_session()
        self.params = params
        self.component_name = self.params.get("component_name")
        self.component_type = self.params.get("component_type")
        self.component_version = self.params.get("component_version")
        self.component_arch = self.params.get("component_arch")
        self.namespace = self.params.get("namespace")
        self.strict_name_search = self.params.get("strict_name_search")

    def execute(self) -> List[Dict[str, Any]]:
        cond = {}
        if not self.strict_name_search:
            cond["re_name"] = self.component_name
        else:
            cond["name"] = self.component_name
        if self.component_version:
            cond["version"] = self.component_version
        if self.component_arch:
            cond["arch"] = self.component_arch
        if self.namespace:
            cond["namespace"] = self.namespace

        components: List[Any] = []
        logger.debug("starting parallel http requests")
        component_cnt = self.corgi_session.components.retrieve_list(**cond).count
        if component_cnt < 3000000:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = []
                components = list()
                for batch in range(0, component_cnt, 120):
                    futures.append(
                        executor.submit(
                            self.corgi_session.components.retrieve_list,
                            **cond,
                            offset=batch,
                            include_fields="link,name,type,version,purl,sources",
                            limit=120,  # noqa
                        )
                    )
                for future in concurrent.futures.as_completed(futures):
                    try:
                        components.extend(future.result().results)
                    except Exception as exc:
                        logger.warning("%r generated an exception: %s" % (future, exc))

        results = []
        for c in components:
            sources = [{"link": source["link"], "purl": source["purl"]} for source in c.sources]
            if self.component_type:
                sources = [
                    source for source in sources if self.component_type.lower() in source["purl"]
                ]
            results.append(
                {
                    "link": c.link,
                    "type": c.type,
                    "name": c.name,
                    "version": c.version,
                    "purl": c.purl,
                    "sources": sources,
                }
            )
        return results


class components_affected_by_specific_cve_query:
    """Given a specific CVE ID, what components are affected?"""

    name = "components_affected_by_specific_cve_query"
    description = "Given a CVE ID, what components are affected?"
    allowed_params = [
        "cve_id",
        "affectedness",
        "affect_resolution",
        "affect_impact",
        "component_type",
        "namespace",
    ]

    def __init__(self, params: dict) -> None:
        self.corgi_session = CorgiService.create_session()
        self.osidb_session = OSIDBService.create_session()
        self.params = params
        self.cve_id = self.params.get("cve_id")
        self.affectedness = self.params.get("affectedness")
        self.affect_resolution = self.params.get("affect_resolution")
        self.affect_impact = self.params.get("affect_impact")

    def execute(self) -> dict:
        cond = {}
        if self.affectedness:
            cond["affectedness"] = self.affectedness
        if self.affect_resolution:
            cond["resolution"] = self.affect_resolution
        if self.affect_impact:
            cond["impact"] = self.affect_impact
        component_type = self.params["component_type"]
        namespace = self.params["namespace"]
        component_cond = {}
        if namespace:
            component_cond["namespace"] = namespace
        if component_type:
            component_cond["type"] = component_type
        flaw = self.osidb_session.flaws.retrieve(self.cve_id)
        affects = self.osidb_session.affects.retrieve_list(
            flaw=flaw.uuid, **cond, limit=1000
        ).results
        results = list()
        for affect in affects:
            try:
                product_version = self.corgi_session.product_versions.retrieve_list(
                    name=affect.ps_module
                ).results[0]
                components = []
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    futures = []
                    for ps in product_version.product_streams:
                        futures.append(
                            executor.submit(
                                self.corgi_session.components.retrieve_list,
                                **component_cond,
                                ofuri=ps["ofuri"],
                                name=affect.ps_component,
                                include_fields="link,purl,name,type",
                                limit=50000,
                            )
                        )
                    for future in concurrent.futures.as_completed(futures):
                        try:
                            for c in future.result().results:
                                components.append(c.to_dict())
                        except Exception as exc:
                            logger.error("%r generated an exception: %s" % (future, exc))
                            exit(0)

                results.append(
                    {
                        "link": f"{OSIDB_API_URL}/osidb/api/v1/affects/{affect.uuid}",
                        "product_version_name": affect.ps_module,
                        "component_name": affect.ps_component,
                        "affectedness": affect.affectedness,
                        "affect_impact": affect.impact,
                        "affect_resolution": affect.resolution,
                        "components": components,
                    }
                )
            except IndexError:
                logger.warning(
                    f"{affect.ps_module} product stream not found in component-registry (may not exist or a community product)."  # noqa
                )

        return {
            "link": f"{OSIDB_API_URL}/osidb/api/v1/flaws/{flaw.cve_id}",
            "cve_id": flaw.cve_id,
            "title": flaw.title,
            "description": flaw.description,
            "affects": results,
        }


class cves_for_specific_component_query:
    """CVEs affecting a specific component?"""

    # include count
    name = "cves_for_specific component"
    description = "Which CVEs affect a specific component ?"
    allowed_params = [
        "purl",
        "affectedness",
    ]

    def __init__(self, params: dict) -> None:
        self.corgi_session = CorgiService.create_session()
        self.osidb_session = OSIDBService.create_session()
        self.params = params

    def execute(self, ctx) -> dict:
        # TODO: add flaw_state, flaw_resolution, affect_impact, affect_resolution
        purl = ctx["purl"]
        affectedness = ctx["affectedness"]
        component = self.corgi_session.components.retrieve_list(purl=purl)
        c = component.additional_properties
        affects: list = list()
        for pv in c["product_versions"]:
            ofuri = "o:redhat"
            for part in pv["name"].split("-"):
                ofuri += f":{part}"

            for affect in self.osidb_session.affects.retrieve_list(
                ps_component=c["name"], ps_module=pv["name"], affectedness=affectedness, limit=10000
            ).results:
                # TODO - OSIDB will be allowing for search of cve by affect which will optimise this
                flaw = self.osidb_session.flaws.retrieve(affect.flaw)
                if flaw:
                    affects.append(
                        {
                            "link_affect": f"{OSIDB_API_URL}/osidb/api/v1/affects/{affect.uuid}",  # noqa
                            "link_cve": f"{OSIDB_API_URL}/osidb/api/v1/flaws/{flaw.cve_id}",
                            "flaw_cve_id": flaw.cve_id,
                            "title": flaw.title,
                            "flaw_state": flaw.state,
                            "flaw_resolution": flaw.resolution,
                            "affect_name": affect.ps_component,
                            "affect_product_version": affect.ps_module,
                            "affect_affectedness": affect.affectedness,
                            "affect_impact": affect.impact,
                            "affect_resolution": affect.resolution,
                        }
                    )
        return {
            "link": f"{CORGI_API_URL}/api/v1/components?purl={c['purl']}",
            "purl": c["purl"],
            "name": c["name"],
            "version": c["version"],
            "nvr": c["nvr"],
            "arch": c["arch"],
            "affects": affects,
        }


class cves_for_specific_product_query:
    name = "cves-for-product"
    description = "What cves affect a specific product ?"
    allowed_params = [
        "product_version_re_name",
        "product_version_name",
        "affectedness",
        "affect_resolution",
        "affect_impact",
        "flaw_state",
        "flaw_resolution",
    ]

    def __init__(self, params: dict) -> None:
        self.corgi_session = CorgiService.create_session()
        self.osidb_session = OSIDBService.create_session()
        self.params = params

    def execute(self, ctx) -> dict:
        product_version_name = ctx["product_version_name"]
        affectedness = ctx["affectedness"]
        impact = ctx["affect_impact"]
        resolution = ctx["affect_resolution"]
        flaw_state = ctx["flaw_state"]
        flaw_resolution = ctx["flaw_resolution"]

        pv = self.corgi_session.product_versions.retrieve_list(name=product_version_name).results[0]

        if pv:
            affects = list()

            affect_filters = {}
            if affectedness:
                affect_filters["affectedness"] = affectedness
            if impact:
                affect_filters["impact"] = impact
            if resolution:
                affect_filters["resolution"] = resolution
            for affect in self.osidb_session.affects.retrieve_list(
                ps_module=product_version_name,
                **affect_filters,
            ).results:
                flaw_filters = {}
                if flaw_state:
                    flaw_filters["state"] = flaw_state
                if flaw_resolution:
                    flaw_filters["resolution"] = flaw_resolution
                flaw = self.osidb_session.flaws.retrieve_list(
                    uuid=affect.flaw,
                    **flaw_filters,
                )
                if flaw.count > 0:
                    f = flaw.results[0]
                    affects.append(
                        {
                            "link_cve": f"{OSIDB_API_URL}/osidb/api/v1/flaws/{f.cve_id}",
                            "flaw_cve_id": f.cve_id,
                            "flaw_state": f.state,
                            "flaw_resolution": f.resolution,
                            "title": f.title,
                            "link_affect": f"{OSIDB_API_URL}/osidb/api/v1/affects/{affect.uuid}",
                            "affect_name": affect.ps_component,
                            "affect_affectedness": affect.affectedness,
                            "affect_impact": affect.impact,
                            "affect_resolution": affect.resolution,
                            "link_component": f"{CORGI_API_URL}/api/v1/components?name={affect.ps_component}",  # noqa
                        }
                    )

        return {
            "link": f"{CORGI_API_URL}/api/v1/product_versions?name={product_version_name}",
            "ofuri": f"{pv.ofuri}",
            "name": product_version_name,
            "description": f"{pv.description}",
            "affects": affects,
        }
