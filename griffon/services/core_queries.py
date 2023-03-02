"""
    read only queries

"""
import concurrent
import logging
from typing import Any, Dict, List

from griffon import CORGI_API_URL, OSIDB_API_URL, CorgiService, OSIDBService

logger = logging.getLogger("griffon")


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
        cond = {"view": "latest"}
        if not self.strict_name_search:
            cond["re_name"] = self.component_name  # type: ignore
        else:
            cond["name"] = self.component_name  # type: ignore
        result = self.corgi_session.components.retrieve_list(**cond, limit=1000)
        return result.results


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
        self.component_type = self.params.get("component_type")
        self.namespace = self.params.get("namespace")

    def execute(self) -> dict:
        cond = {}
        if self.affectedness:
            cond["affectedness"] = self.affectedness
        if self.affect_resolution:
            cond["resolution"] = self.affect_resolution
        if self.affect_impact:
            cond["impact"] = self.affect_impact

        component_cond = {}
        if self.namespace:
            component_cond["namespace"] = self.namespace
        if self.component_type:
            component_cond["type"] = self.component_type

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
        "component_name",
        "purl",
        "flaw_state",
        "flaw_impact",
        "flaw_resolution",
        "affectedness",
        "affect_resolution",
        "affect_impact",
        "strict_name_search",
    ]

    def __init__(self, params: dict) -> None:
        self.corgi_session = CorgiService.create_session()
        self.osidb_session = OSIDBService.create_session()
        self.params = params
        self.component_name = self.params.get("component_name")
        self.purl = self.params.get("purl")
        self.flaw_state = self.params.get("flaw_state")
        self.flaw_impact = self.params.get("flaw_impact")
        self.flaw_resolution = self.params.get("flaw_resolution")
        self.affectedness = self.params.get("affectedness")
        self.affect_resolution = self.params.get("affect_resolution")
        self.affect_impact = self.params.get("affect_impact")

    def execute(self) -> List[Dict[str, Any]]:
        components = []
        if self.component_name:
            affects: list = []
            # component = self.corgi_session.components.retrieve_list(name=self.component_name)
            cond = {}
            cond["ps_component"] = self.component_name
            if self.affectedness:
                cond["affectedness"] = self.affectedness
            if self.affect_resolution:
                cond["resolution"] = self.affect_resolution
            if self.affect_impact:
                cond["impact"] = self.affect_impact

            for affect in self.osidb_session.affects.retrieve_list(
                **cond,
                limit=50,
            ).results:
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
            components.append(
                {
                    "link": f"{CORGI_API_URL}/api/v1/components?purl=",
                    "name": self.component_name,
                    "affects": affects,
                }
            )

        if self.purl:
            pass

        return components


class cves_for_specific_product_query:
    name = "cves-for-product"
    description = "What cves affect a specific product ?"
    allowed_params = [
        "product_version_name",
        "ofuri",
        "flaw_state",
        "flaw_impact",
        "flaw_resolution",
        "affectedness",
        "affect_resolution",
        "affect_impact",
        "strict_name_search",
    ]

    def __init__(self, params: dict) -> None:
        self.corgi_session = CorgiService.create_session()
        self.osidb_session = OSIDBService.create_session()
        self.params = params
        self.product_version_name = self.params.get("product_version_name")
        self.ofuri = self.params.get("ofuri")
        self.flaw_state = self.params.get("flaw_state")
        self.flaw_impact = self.params.get("flaw_impact")
        self.flaw_resolution = self.params.get("flaw_resolution")
        self.affectedness = self.params.get("affectedness")
        self.affect_resolution = self.params.get("affect_resolution")
        self.affect_impact = self.params.get("affect_impact")

    def execute(self) -> List[Dict[str, Any]]:
        components = []
        if self.product_version_name:
            affects: list = []
            # component = self.corgi_session.components.retrieve_list(name=self.component_name)
            cond = {}
            cond["ps_module"] = self.product_version_name
            if self.affectedness:
                cond["affectedness"] = self.affectedness
            if self.affect_resolution:
                cond["resolution"] = self.affect_resolution
            if self.affect_impact:
                cond["impact"] = self.affect_impact

            for affect in self.osidb_session.affects.retrieve_list(
                **cond,
                limit=10,
            ).results:
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
            components.append(
                {
                    "link": f"{CORGI_API_URL}/api/v1/product_version?ofuri=",
                    "name": self.product_version_name,
                    "affects": affects,
                }
            )

        if self.ofuri:
            pass

        return components
