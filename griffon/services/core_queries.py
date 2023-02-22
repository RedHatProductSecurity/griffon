"""
    read only queries

"""
import concurrent
import logging
from typing import Any, Dict, List

from griffon import CORGI_API_URL, OSIDB_API_URL, CorgiService, OSIDBService

logger = logging.getLogger("rich")


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
        "component_re_name",
        "component_name",
        "purl",
        "arch",
        "namespace",
        "component_type",
    ]

    def __init__(self, params: dict) -> None:
        self.corgi_session = CorgiService.create_session()
        self.params = params

    def execute(self) -> dict:
        purl = self.params["purl"]
        c = self.corgi_session.components.retrieve_list(
            purl=purl,
        )
        return c["product_streams"]


class products_containing_component_query:
    """What products contain a component?"""

    name = "products_containing_component_query"
    description = "What products contain a component?"
    allowed_params = [
        "component_re_name",
        "component_name",
        "purl",
        "arch",
        "namespace",
        "component_type",
    ]

    def __init__(self, params: dict) -> None:
        self.corgi_session = CorgiService.create_session()
        self.params = params

    def execute(self) -> List[Dict[str, Any]]:
        component_name = self.params["component_name"]
        component_re_name = self.params["component_re_name"]
        component_type = self.params["component_type"]
        ns = self.params["namespace"]
        cond = {}
        if component_re_name:
            cond["re_name"] = component_re_name
        else:
            cond["name"] = component_name
        if component_type:
            cond["type"] = component_type
        if ns == "REDHAT":
            cond["namespace"] = "REDHAT"

        components: List[Any] = []
        logger.debug("starting parallel http requests")
        component_cnt = self.corgi_session.components.retrieve_list(**cond).count
        if component_cnt < 3000000:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = []
                components = list()
                for batch in range(0, component_cnt, 30):
                    futures.append(
                        executor.submit(
                            self.corgi_session.components.retrieve_list,
                            **cond,
                            offset=batch,
                            include_fields="uuid,name,namespace,purl,nvr,related_url,software_build,product_streams,sources",  # noqa
                            limit=30,
                        )
                    )
                for future in concurrent.futures.as_completed(futures):
                    try:
                        components.extend(future.result().results)
                    except Exception as exc:
                        logger.warning("%r generated an exception: %s" % (future, exc))

        results = []
        for component in components:
            logger.debug(component.sources)
            sources = []
            for source in component.sources:
                if "arch=src" in source["purl"]:
                    sources.append(source["purl"])
            for ps in component.product_streams:
                result = {
                    "link": ps["link"],
                    "ofuri": ps["ofuri"],
                    "name": ps["name"],
                    "component_purl": component.purl,
                    "component_name": component.name,
                    "component_related_url": component.related_url,
                    "component_software_build": component.software_build.to_dict(),
                    "component_root_components": sources,
                }
                results.append(result)
        return results


class product_stream_summary:
    """retrieve product_stream summary"""

    name = "product_stream_summary"
    description = "retrieve product_stream summary"
    allowed_params = ["product_stream_re_name", "product_stream_name", "ofuri", "inactive"]

    def __init__(self, params: dict) -> None:
        self.corgi_session = CorgiService.create_session()
        self.params = params

    def execute(self) -> dict:
        cond = {}
        product_stream_name = self.params["product_stream_name"]
        ofuri = self.params["ofuri"]
        if product_stream_name:
            cond["name"] = product_stream_name
        if ofuri:
            cond["ofuri"] = ofuri
        # TODO - corgi bindings need to support ofuri in product_streams
        product_stream = self.corgi_session.product_streams.retrieve_list(**cond)
        components_cnt = self.corgi_session.components.retrieve_list(
            ofuri=product_stream["ofuri"], view="summary", limit=1
        ).count
        return {
            "link": product_stream["link"],
            "ofuri": product_stream["ofuri"],
            "name": product_stream["name"],
            "product": product_stream["products"][0]["name"],
            "product_version": product_stream["product_versions"][0]["name"],
            "brew_tags": list(product_stream["brew_tags"].keys()),
            "build_count": product_stream["build_count"],
            "latest_component_count": components_cnt,
            "manifest_link": product_stream["manifest"],
            "shipped_components_link": "tbd",
            "latest_components_link": product_stream["components"],
            "all_components_link": f"{CORGI_API_URL}/api/v1/components?product_streams={product_stream['ofuri']}&include_fields=link,name,purl",  # noqa
        }


class components_containing_specific_component_query:
    """What components contain a specific component?"""

    name = "components_containing_specific_component_query"
    description = "What components contain a specific component?"
    allowed_params = ["component_re_name", "component_name", "purl", "component_type", "namespace"]

    def __init__(self, params: dict):
        self.corgi_session = CorgiService.create_session()
        self.params = params

    def execute(self) -> dict:
        purl = self.params["purl"]
        if purl:
            c = self.corgi_session.components.retrieve_list(
                purl=purl,
            )
            component_type = self.params["component_type"]
            sources = c["sources"]
            if component_type:
                sources = [source for source in sources if component_type.lower() in source["purl"]]
        return {
            "link": c["link"],
            "type": component_type,
            "name": c["name"],
            "purl": c["purl"],
            "sources": sources,
        }


class components_containing_component_query:
    """What components contain a component?"""

    name = "components_containing_component_query"
    description = "What components contain a component?"
    allowed_params = ["component_re_name", "component_name", "purl", "component_type", "namespace"]

    def __init__(self, params: dict) -> None:
        self.corgi_session = CorgiService.create_session()
        self.params = params

    def execute(self) -> List[Dict[str, Any]]:
        component_type = self.params["component_type"]
        component_name = self.params["component_name"]
        component_re_name = self.params["component_re_name"]
        namespace = self.params["namespace"]

        cond = {}
        if component_re_name:
            cond["re_name"] = component_re_name
        else:
            cond["name"] = component_name

        if namespace:
            cond["namespace"] = namespace

        components: List[Any] = []
        logger.debug("starting parallel http requests")
        component_cnt = self.corgi_session.components.retrieve_list(**cond).count
        if component_cnt < 3000000:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = []
                components = list()
                for batch in range(0, component_cnt, 30):
                    futures.append(
                        executor.submit(
                            self.corgi_session.components.retrieve_list,
                            **cond,
                            offset=batch,
                            include_fields="link,name,purl,sources",
                            limit=30,  # noqa
                        )
                    )
                for future in concurrent.futures.as_completed(futures):
                    try:
                        components.extend(future.result().results)
                    except Exception as exc:
                        logger.warning("%r generated an exception: %s" % (future, exc))

        results = []
        for c in components:
            sources = []
            for source in c.sources:
                sources.append({"link": source["link"], "purl": source["purl"]})
            if component_type:
                sources = [source for source in sources if component_type.lower() in source["purl"]]
            results.append(
                {
                    "link": c.link,
                    "name": c.name,
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

    def execute(self) -> dict:
        cve_id = self.params["cve_id"]
        affectedness = self.params["affectedness"]
        affect_resolution = self.params["affect_resolution"]
        affect_impact = self.params["affect_impact"]
        cond = {}
        if affectedness:
            cond["affectedness"] = affectedness
        if affect_resolution:
            cond["resolution"] = affect_resolution
        if affect_impact:
            cond["impact"] = affect_impact
        component_type = self.params["component_type"]
        namespace = self.params["namespace"]
        component_cond = {}
        if namespace:
            component_cond["namespace"] = namespace
        if component_type:
            component_cond["type"] = component_type
        flaw = self.osidb_session.flaws.retrieve(cve_id)
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
