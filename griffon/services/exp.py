"""
    read only queries

"""
import concurrent
import logging

from griffon import CORGI_API_URL, OSIDB_API_URL, CorgiService, OSIDBService

logger = logging.getLogger("rich")


class cves_for_specific_component_query:
    """CVEs affecting a specific component?"""

    # include count
    name = "cves_for_specific component"
    description = "Which CVEs affect a specific component ?"

    def __init__(self) -> None:
        self.corgi_session = CorgiService.create_session()
        self.osidb_session = OSIDBService.create_session()

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


class components_affected_by_specific_cve_query:
    """Given a specific CVE ID, what components are affected?"""

    name = "components_affected_by_specific_cve_query"
    description = "Given a CVE ID, what components are affected?"

    def __init__(self) -> None:
        self.corgi_session = CorgiService.create_session()
        self.osidb_session = OSIDBService.create_session()

    # TODO - needs to be optimised
    def execute(self, ctx) -> dict:
        cve_id = ctx["cve_id"]
        flaw = self.osidb_session.flaws.retrieve_list(cve_id=cve_id).results[0]
        affects = self.osidb_session.affects.retrieve_list(flaw=flaw.uuid, limit=10000).results
        components: list = list()
        for affect in affects:
            product_versions = self.corgi_session.product_versions.retrieve_list(
                name=affect.ps_module
            ).results
            for pv in product_versions:
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    futures = []
                    for ps in pv.product_streams:
                        futures.append(
                            executor.submit(
                                self.corgi_session.components.retrieve_list,
                                ofuri=ps["ofuri"],
                                name=affect.ps_component,
                                view="summary",
                                limit=10000,
                            )
                        )
                    for future in concurrent.futures.as_completed(futures):
                        try:
                            for c in future.result().results:
                                components.append(c.purl)
                        except Exception as exc:
                            logger.error("%r generated an exception: %s" % (future, exc))
                            exit(0)

        distinct_components: list = list()
        for purl in components:
            distinct_components.append(
                {
                    "link": f"{CORGI_API_URL}/api/v1/components?purl={purl}",
                    "purl": purl,
                }
            )
        return {
            "link": f"{OSIDB_API_URL}/osidb/api/v1/flaws/{flaw.cve_id}",
            "cve_id": flaw.cve_id,
            "title": flaw.title,
            "description": flaw.description,
            "components": distinct_components,
        }


class cves_for_specific_product_query:
    name = "cves-for-product"
    description = "What cves affect a specific product ?"
    params = []

    def __init__(self) -> None:
        self.corgi_session = CorgiService.create_session()
        self.osidb_session = OSIDBService.create_session()

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
