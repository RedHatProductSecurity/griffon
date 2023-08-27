"""
    read only queries

"""
import logging
from datetime import datetime

import requests

from griffon import OSIDB_API_URL, CorgiService, OSIDBService

logger = logging.getLogger("griffon")


class example_affects_report:
    """ """

    name = "example_affects_report"
    description = " "
    allowed_params = [
        "product_version_name",
        "show_components",
        "all",
        "show_products",
        "purl",
        "name",
        "ofuri",
        "product_name",
    ]

    def __init__(self, params) -> None:
        self.corgi_session = CorgiService.create_session()
        self.osidb_session = OSIDBService.create_session()
        self.params = params
        self.product_version_name = self.params.get("product_version_name")
        self.show_components = self.params.get("show_components")
        self.show_products = self.params.get("show_products")
        self.all = self.params.get("all")
        self.purl = self.params.get("purl")
        self.component_name = self.params.get("name")
        self.ofuri = self.params.get("ofuri")
        self.product_name = self.params.get("product_name")

    def generate(self) -> dict:
        affects = self.osidb_session.affects.retrieve_list()

        affects_affected = self.osidb_session.affects.retrieve_list(affectedness="AFFECTED")

        # TODO osidb_session.affects does not support include_fields, do it manually for now
        affect_critical_res = requests.get(
            f"{OSIDB_API_URL}/osidb/api/v1/affects?affectedness=AFFECTED&impact=CRITICAL&include_fields=ps_component,ps_module,impact&limit=10000"  # noqa
        )
        affects_critical = affect_critical_res.json()
        critical_components = {}
        critical_products = {}
        for affect in affects_critical["results"]:
            component_name = affect.get("ps_component", "no_name")
            if component_name not in critical_components:
                critical_components[component_name] = 0
            critical_components[component_name] += 1

            product_version_name = affect.get("ps_module", "no_name")
            if product_version_name not in critical_products:
                critical_products[product_version_name] = 0
            critical_products[product_version_name] += 1

        top_critical_component = max(critical_components, key=critical_components.get)  # type: ignore # noqa
        top_critical_product = max(critical_products, key=critical_products.get)  # type: ignore

        affect_important_res = requests.get(
            f"{OSIDB_API_URL}/osidb/api/v1/affects?affectedness=AFFECTED&impact=IMPORTANT&include_fields=ps_component,ps_module,impact&limit=10000"  # noqa
        )
        affects_important = affect_important_res.json()
        important_components = {}
        important_products = {}
        for affect in affects_important["results"]:
            component_name = affect.get("ps_component", "no_name")
            if component_name not in important_components:
                important_components[component_name] = 0
            important_components[component_name] += 1

            product_version_name = affect.get("ps_module", "no_name")
            if product_version_name not in important_products:
                important_products[product_version_name] = 0
            important_products[product_version_name] += 1
        top_important_component = max(important_components, key=important_components.get)  # type: ignore # noqa
        top_important_product = max(important_products, key=important_products.get)  # type: ignore # noqa

        affect_moderate_res = requests.get(
            f"{OSIDB_API_URL}/osidb/api/v1/affects?affectedness=AFFECTED&impact=MODERATE&include_fields=ps_component,ps_module,impact&limit=10000"  # noqa
        )
        affects_moderate = affect_moderate_res.json()
        moderate_components = {}
        moderate_products = {}
        for affect in affects_moderate["results"]:
            component_name = affect.get("ps_component", "no_name")
            if component_name not in moderate_components:
                moderate_components[component_name] = 0
            moderate_components[component_name] += 1

            product_version_name = affect.get("ps_module", "no_name")
            if product_version_name not in moderate_products:
                moderate_products[product_version_name] = 0
            moderate_products[product_version_name] += 1
        top_moderate_component = max(moderate_components, key=moderate_components.get)  # type: ignore # noqa
        top_moderate_product = max(moderate_products, key=moderate_products.get)  # type: ignore

        affect_low_res = requests.get(
            f"{OSIDB_API_URL}/osidb/api/v1/affects?affectedness=AFFECTED&impact=LOW&include_fields=ps_component,ps_module,impact&limit=10000"  # noqa
        )
        affects_low = affect_low_res.json()
        low_components = {}
        low_products = {}
        for affect in affects_low["results"]:
            component_name = affect.get("ps_component", "no_name")
            if component_name not in low_components:
                low_components[component_name] = 0
            low_components[component_name] += 1

            product_version_name = affect.get("ps_module", "no_name")
            if product_version_name not in low_products:
                low_products[product_version_name] = 0
            low_products[product_version_name] += 1
        top_low_component = max(low_components, key=low_components.get)  # type: ignore
        top_low_product = max(low_products, key=low_products.get)  # type: ignore

        critical = {
            "affected": affects_critical["count"],
            "top_component": top_critical_component,
            "top_product": top_critical_product,
        }
        important = {
            "affected": affects_important["count"],
            "top_component": top_important_component,
            "top_product": top_important_product,
        }
        moderate = {
            "affected": affects_moderate["count"],
            "top_component": top_moderate_component,
            "top_product": top_moderate_product,
        }
        low = {
            "affected": affects_low["count"],
            "top_component": top_low_component,
            "top_product": top_low_product,
        }

        if self.show_components:
            critical["components"] = critical_components
            important["components"] = important_components
            moderate["components"] = moderate_components
            low["components"] = low_components

        if self.show_products:
            critical["products"] = critical_products
            important["products"] = important_products
            moderate["products"] = moderate_products
            low["products"] = low_products

        report = {
            "title": "Example Affects report",
            "ts": str(datetime.now()),
            "total_affects": affects.count,
            "total_affected": affects_affected.count,
            "critical": critical,
            "important": important,
            "moderate": moderate,
            "low": low,
        }

        if self.purl:
            report["purl"] = self.purl
        if self.component_name:
            report["component_name"] = self.component_name
        if self.ofuri:
            report["product_ofuri"] = self.ofuri
        if self.product_name:
            report["product"] = self.product_name

        return {
            "title": "Example Affects report",
            "ts": str(datetime.now()),
            "total_affects": affects.count,
            "total_affected": affects_affected.count,
            "critical": critical,
            "important": important,
            "moderate": moderate,
            "low": low,
        }


class entity_report:
    """ """

    name = "entity_report"
    description = " "
    allowed_params = ["all"]

    def __init__(self, params) -> None:
        self.corgi_session = CorgiService.create_session()
        self.osidb_session = OSIDBService.create_session()
        self.params = params

    def generate(self) -> dict:
        component_arches = CorgiService.get_component_arches()
        component_types = [
            component_type.value for component_type in CorgiService.get_component_types()
        ]
        corgi_status = self.corgi_session.status()
        active_product_streams_count = self.corgi_session.product_streams.retrieve_list().count
        component_instances_count = self.corgi_session.components.retrieve_list(limit=1).count

        # get src RPM count
        rpmcomponents_cnt = self.corgi_session.components.count(
            root_components="True",
            type="RPM",
        )
        # get OCI noarch count
        ocicomponents_cnt = self.corgi_session.components.count(
            root_components="True",
            type="OCI",
        )
        # get NPM noarch count
        npmcomponents_cnt = self.corgi_session.components.count(
            type="NPM",
        )
        # get GOLANG noarch count
        golangcomponents_cnt = self.corgi_session.components.count(
            type="GOLANG",
        )
        # get GENERIC count
        genericcomponents_cnt = self.corgi_session.components.count(
            type="GENERIC",
        )
        # get GEM count
        gemcomponents_cnt = self.corgi_session.components.count(
            type="GEM",
        )
        # get CARGO count
        cargocomponents_cnt = self.corgi_session.components.count(
            type="CARGO",
        )
        # get GITHUB count
        githubcomponents_cnt = self.corgi_session.components.count(
            type="GITHUB",
        )
        # get MAVEN count
        mavencomponents_cnt = self.corgi_session.components.count(
            type="MAVEN",
        )
        # get PYPI count
        pypicomponents_cnt = self.corgi_session.components.count(
            type="PYPI",
        )
        # get RPMMOD count
        rpmmodcomponents_cnt = self.corgi_session.components.count(
            type="RPMMOD",
        )

        total_component_cnt = (
            rpmcomponents_cnt
            + ocicomponents_cnt
            + npmcomponents_cnt
            + golangcomponents_cnt
            + gemcomponents_cnt
            + cargocomponents_cnt
            + githubcomponents_cnt
            + mavencomponents_cnt
            + pypicomponents_cnt
            + rpmmodcomponents_cnt
        )

        return {
            "corgi": {
                "title": "Entity report",
                "ts": str(datetime.now()),
                "db_size": corgi_status["db_size"],
                "components": {
                    "types": component_types,
                    "arches": component_arches,
                    "total_component_instances": component_instances_count,
                    "total_distinct_components": total_component_cnt,
                    "rpm_root_components": rpmcomponents_cnt,
                    "oci_root_components": ocicomponents_cnt,
                    "npm_components": npmcomponents_cnt,
                    "golang_components": golangcomponents_cnt,
                    "generic_components": genericcomponents_cnt,
                    "gem_components": gemcomponents_cnt,
                    "cargo_components": cargocomponents_cnt,
                    "github_components": githubcomponents_cnt,
                    "maven_components": mavencomponents_cnt,
                    "pypi_components": pypicomponents_cnt,
                    "rpmmod_components": rpmmodcomponents_cnt,
                },
                "products": {
                    "products": corgi_status["products"]["count"],
                    "product_versions": corgi_status["product_versions"]["count"],
                    "active_product_streams": active_product_streams_count,
                    "product_streams": corgi_status["product_streams"]["count"],
                    "product_variants": corgi_status["product_variants"]["count"],
                    "channels": corgi_status["channels"]["count"],
                },
            }
        }


class license_report:
    """ """

    name = "license_report"
    description = " "
    allowed_params = ["product_stream_name", "purl", "exclude_children"]

    def __init__(self, params) -> None:
        self.corgi_session = CorgiService.create_session()
        self.params = params
        self.product_stream_name = params.get("product_stream_name")
        self.purl = params.get("purl")
        self.exclude_children = params.get("exclude_children")

    def generate(self) -> dict:
        output = {}
        component_filter = {
            "include_fields": "uuid,purl,type,license_concluded,license_declared,related_url,download_url,software_build.build_id",  # noqa
        }
        if self.purl:
            component_filter["purl"] = self.purl
        if self.product_stream_name:
            product_stream = self.corgi_session.product_streams.retrieve_list(
                name=self.product_stream_name
            )
            stream_ofuri = product_stream["ofuri"]
            component_filter["ofuri"] = stream_ofuri
        search_components = self.corgi_session.components.retrieve_list_iterator_async(
            **component_filter
        )
        for component in search_components:
            purl = component.purl
            output[purl] = {
                "license_declared": component.license_declared,
                "related_url": component.related_url,
                "build_id": component.software_build.build_id,
            }
            if component.license_concluded:
                # Some components can't be scanned, e.g. binary RPMs
                output[purl]["license_concluded"] = component.license_concluded
            if str(component.type) not in ("RPM", "RPMMOD") and (
                # Report container's exact repository_url if present
                # Container Catalog search page is used as a fallback
                # Just ignore it if no specific URL is available
                component.download_url
                != "https://catalog.redhat.com/software/containers/search"
            ):
                output[purl]["download_url"] = component.download_url

            children = []
            provides_filter = {
                "sources": purl,
                "include_fields": "purl,type,license_concluded,license_declared,related_url,download_url",  # noqa
            }
            provides_components = self.corgi_session.components.retrieve_list_iterator_async(
                **provides_filter
            )
            for c in provides_components:
                child = {
                    "purl": c.purl,
                    "license_declared": c.license_declared,
                    "related_url": c.related_url,
                }
                if c.license_concluded:
                    # Some components can't be scanned, e.g. binary RPMs
                    child["license_concluded"] = c.license_concluded
                if str(c.type) not in ("RPM", "RPMMOD") and (
                    # Report container's exact repository_url if present
                    # Container Catalog search page is used as a fallback
                    # Just ignore it if no specific URL is available
                    c.download_url
                    != "https://catalog.redhat.com/software/containers/search"
                ):
                    child["download_url"] = c.download_url
                children.append(child)
            output[purl]["children"] = children
        return output
