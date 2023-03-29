"""
    read only queries

"""
import concurrent
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
        component_cnt = self.corgi_session.components.retrieve_list(
            arch="src", namespace="REDHAT", type="RPM", include_fields="name"
        ).count
        components = list()
        if component_cnt < 3000000:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = []
                for batch in range(0, component_cnt, 5000):
                    futures.append(
                        executor.submit(
                            self.corgi_session.components.retrieve_list,
                            arch="src",
                            namespace="REDHAT",
                            type="RPM",
                            include_fields="name",
                            offset=batch,
                            limit=5000,  # noqa
                        )
                    )

                for future in concurrent.futures.as_completed(futures):
                    try:
                        components.extend(future.result().results)
                    except Exception as exc:
                        logger.warning("%r generated an exception: %s" % (future, exc))

        # # get OCI noarch count
        # component_cnt = self.corgi_session.components.retrieve_list(
        #     arch="noarch", type="OCI", include_fields="name"
        # ).count
        # oci_components = list()
        # if component_cnt < 3000000:
        #     with concurrent.futures.ThreadPoolExecutor() as executor:
        #         futures = []
        #         for batch in range(0, component_cnt, 3000):
        #             futures.append(
        #                 executor.submit(
        #                     self.corgi_session.components.retrieve_list,
        #                     arch="noarch",
        #                     type="OCI",
        #                     include_fields="name",
        #                     offset=batch,
        #                     limit=3000,  # noqa
        #                 )
        #             )
        #
        #         for future in concurrent.futures.as_completed(futures):
        #             try:
        #                 oci_components.extend(future.result().results)
        #             except Exception as exc:
        #                 logger.warning("%r generated an exception: %s" % (future, exc))

        # # get NPM noarch count
        # component_cnt = self.corgi_session.components.retrieve_list(type="NPM",
        #                                                             include_fields="name").count
        # npm_components = list()
        # if component_cnt < 3000000:
        #     with concurrent.futures.ThreadPoolExecutor() as executor:
        #         futures = []
        #         for batch in range(0, component_cnt, 3000):
        #             futures.append(
        #                 executor.submit(
        #                     self.corgi_session.components.retrieve_list,
        #                     type="NPM", include_fields="name",
        #                     offset=batch,
        #                     limit=3000,  # noqa
        #                 )
        #             )
        #
        #         for future in concurrent.futures.as_completed(futures):
        #             try:
        #                 npm_components.extend(future.result().results)
        #             except Exception as exc:
        #                 logger.warning("%r generated an exception: %s" % (future, exc))

        # get GOLANG noarch count
        # component_cnt = self.corgi_session.components.retrieve_list(type="GOLANG",
        #                                                             include_fields="name").count
        # golang_components = list()
        # if component_cnt < 3000000:
        #     with concurrent.futures.ThreadPoolExecutor() as executor:
        #         futures = []
        #         for batch in range(0, component_cnt, 3000):
        #             futures.append(
        #                 executor.submit(
        #                     self.corgi_session.components.retrieve_list,
        #                     type="GOLANG", include_fields="name",
        #                     offset=batch,
        #                     limit=3000,  # noqa
        #                 )
        #             )
        #
        #         for future in concurrent.futures.as_completed(futures):
        #             try:
        #                 golang_components.extend(future.result().results)
        #             except Exception as exc:
        #                 logger.warning("%r generated an exception: %s" % (future, exc))

        rpm_components_cnt: int = len(list(set([component.name for component in components])))

        # TODO: baking these values in as we will eventually process these server side
        oci_components_cnt: int = 2873
        npm_components_cnt: int = 8677
        golang_components_cnt: int = 48359

        total_component_cnt = (
            rpm_components_cnt + oci_components_cnt + npm_components_cnt + golang_components_cnt
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
                    "rpm_components": rpm_components_cnt,
                    "oci_components": oci_components_cnt,
                    "npm_components": npm_components_cnt,
                    "golang_components": golang_components_cnt,
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
        filter = {
            "include_fields": "uuid,purl,type,license_declared,related_url,software_build.build_id,provides,download_url",  # noqa
        }
        if self.purl:
            filter["purl"] = self.purl
        if self.product_stream_name:
            product_stream = self.corgi_session.product_streams.retrieve_list(
                name=self.product_stream_name
            )
            stream_ofuri = product_stream["ofuri"]
            filter["ofuri"] = stream_ofuri
        initial_component = self.corgi_session.components.retrieve_list(**filter)
        component_cnt = initial_component.count
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            components = list()
            if self.purl:
                components.append(
                    self.corgi_session.components.retrieve(initial_component.to_dict()["uuid"])
                )
            else:
                for batch in range(0, component_cnt, 120):
                    futures.append(
                        executor.submit(
                            self.corgi_session.components.retrieve_list,
                            **filter,
                            offset=batch,
                            limit=120,
                        )
                    )
                for future in concurrent.futures.as_completed(futures):
                    try:
                        components.extend(future.result().results)
                    except Exception as exc:
                        logger.warning("%r generated an exception: %s" % (future, exc))

            for component in components:
                purl = component.purl
                logger.debug(purl)
                output[purl] = {
                    "license_declared": component.license_declared,
                    "related_url": component.related_url,
                    "build_id": component.software_build.build_id,
                }
                if str(component.type) in ["GEM", "GOLANG", "NPM", "PYPI"]:
                    output[purl]["upstream_url"] = component.download_url

                children = []
                provides_filter = {
                    "sources": purl,
                    "include_fields": "purl,type,license_declared,related_url,download_url",
                }
                provides_cnt = self.corgi_session.components.retrieve_list(**provides_filter).count
                logger.debug(provides_cnt)

                if not self.exclude_children:
                    futures_children = []
                    for batch in range(0, provides_cnt, 120):
                        futures_children.append(
                            executor.submit(
                                self.corgi_session.components.retrieve_list,
                                **provides_filter,
                                offset=batch,
                                limit=120,
                            )
                        )
                    for future in concurrent.futures.as_completed(futures_children):
                        try:
                            for c in future.result().results:
                                child = {
                                    "purl": c.purl,
                                    "license_declared": c.license_declared,
                                    "related_url": c.related_url,
                                }
                                if str(c.type) in ["GEM", "GOLANG", "NPM", "PYPI"]:
                                    child["upstream_url"] = c.download_url
                                children.append(child)
                        except Exception as exc:
                            logger.warning("%r generated an exception: %s" % (future, exc))

                    output[purl]["children"] = children
        return output
