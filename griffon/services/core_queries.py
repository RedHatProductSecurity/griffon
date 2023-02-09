"""
    read only queries

"""
import logging

from griffon import CORGI_API_URL, OSIDB_API_URL, CorgiService, OSIDBService

logger = logging.getLogger("rich")


class products_versions_affected_by_specific_cve_query:
    """Given a specific CVE ID, what products are affected?"""

    name = "product-versions-affected-by-specific-cve"
    description = "Given a specific CVE ID, what product versions are affected?"
    params = ["cve_id"]

    def __init__(self) -> None:
        self.osidb_session = OSIDBService.create_session()

    def execute(self, ctx) -> dict:
        cve_id = ctx["cve_id"]
        flaw = self.osidb_session.flaws.retrieve(cve_id)
        pv_names = list()
        for affect in flaw.affects:
            pv_names.append(affect.ps_module)
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
        }


class products_containing_specific_component_query:
    """What products contain a specific component?"""

    name = "products_containing_specific_component_query"
    description = "What products contain a specific component?"
    params = ["purl"]

    def __init__(self) -> None:
        self.corgi_session = CorgiService.create_session()

    def execute(self, ctx) -> dict:

        # for param in required_params:

        purl = ctx["purl"]
        c = self.corgi_session.components.retrieve_list(
            purl=purl,
        )
        return c["product_streams"]


class components_containing_specific_component_query:
    """What components contain a specific component?"""

    name = "components_containing_specific_component_query"
    description = "What components contain a specific component?"
    params = ["purl"]

    def __init__(self) -> None:
        self.corgi_session = CorgiService.create_session()

    def execute(self, ctx) -> dict:
        purl = ctx["purl"]
        c = self.corgi_session.components.retrieve_list(
            purl=purl,
        )
        return {
            "link": c["link"],
            "name": c["name"],
            "purl": c["purl"],
            "sources": c["sources"],
        }


class products_containing_component_query:
    """What products contain a component?"""

    name = "products_containing_component_query"
    description = "What products contain a component?"
    params = ["name"]

    def __init__(self) -> None:
        self.corgi_session = CorgiService.create_session()

    def execute(self, ctx) -> dict:
        component_name = ctx["component_name"]
        components = self.corgi_session.components.retrieve_list(
            name=component_name,
            view="product",
        )
        results = []
        for c in components.results:
            results.append(
                {
                    "link": c.link,
                    "ofuri": c["ofuri"],
                    "name": c.name,
                    "component_link": c["component_link"],
                    "component_purl": c["component_purl"],
                }
            )
        return results


class components_containing_component_query:
    """What components contain a component?"""

    name = "components_containing_component_query"
    description = "What components contain a component?"
    params = ["name"]

    def __init__(self) -> None:
        self.corgi_session = CorgiService.create_session()

    def execute(self, ctx) -> dict:
        component_name = ctx["component_name"]
        # TODO: narrow down with includes_fields when it emerges in corgi bindings
        components = self.corgi_session.components.retrieve_list(
            name=component_name, namespace="REDHAT"
        )
        results = []
        for c in components.results:
            sources = []
            for source in c.sources:
                sources.append({"link": source["link"], "purl": source["purl"]})
            results.append(
                {
                    "link": c.link,
                    "name": c.name,
                    "purl": c.purl,
                    "sources": sources,
                }
            )
        return results


class product_stream_summary:
    """retrieve product_stream summary"""

    name = "product_stream_summary"
    description = "retrieve product_stream summary"

    def __init__(self) -> None:
        self.corgi_session = CorgiService.create_session()

    def execute(self, product_stream_name, ofuri) -> dict:
        cond = {}
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
