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
    allowed_params = ["show_components", "show_products", "purl", "name", "ofuri", "product_name"]

    def __init__(self, params) -> None:
        self.corgi_session = CorgiService.create_session()
        self.osidb_session = OSIDBService.create_session()
        self.params = params

    def generate(self) -> dict:

        show_components = self.params["show_components"]
        show_products = self.params["show_products"]
        purl = self.params["purl"]
        component_name = self.params["name"]
        ofuri = self.params["ofuri"]
        product_name = self.params["product_name"]

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

        if show_components:
            critical["components"] = critical_components
            important["components"] = important_components
            moderate["components"] = moderate_components
            low["components"] = low_components

        if show_products:
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

        if purl:
            report["purl"] = purl
        if component_name:
            report["component_name"] = component_name
        if ofuri:
            report["product_ofuri"] = ofuri
        if product_name:
            report["product"] = product_name

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
