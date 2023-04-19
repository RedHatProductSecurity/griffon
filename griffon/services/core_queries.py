"""
    read only queries

"""
import concurrent
import logging
import re
from typing import Any, Dict, List

import requests
from component_registry_bindings.bindings.python_client.models import Component

from griffon import (
    COMMUNITY_COMPONENTS_API_URL,
    CORGI_API_URL,
    OSIDB_API_URL,
    CommunityComponentService,
    CorgiService,
    OSIDBService,
)

logger = logging.getLogger("griffon")


class product_stream_summary:
    """retrieve product_stream summary"""

    name = "product_stream_summary"
    description = "retrieve product_stream summary"
    allowed_params = ["strict_name_search", "all", "product_stream_name", "ofuri"]

    def __init__(self, params: dict) -> None:
        self.corgi_session = CorgiService.create_session()
        self.params = params
        self.product_stream_name = self.params.get("product_stream_name")
        self.ofuri = self.params.get("ofuri")
        self.strict_name_search = self.params.get("strict_name_search", None)
        self.all = self.params.get("all", None)

    def execute(self) -> List[Dict[str, Any]]:
        cond = {}

        if self.ofuri:
            cond["ofuri"] = self.ofuri
        elif not self.strict_name_search:
            if not self.all:
                cond["re_name"] = self.product_stream_name
        else:
            if not self.all:
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
                    # "build_count": ps.build_count,
                    "manifest_link": ps.manifest,
                    "latest_components_link": f"{CORGI_API_URL}/api/v1/components?ofuri={ps.ofuri}&view=summary",  # noqa
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
                "latest_components_link": f"{CORGI_API_URL}/api/v1/components?ofuri={product_streams['ofuri']}&view=summary",  # noqa
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
        self.corgi_session = CorgiService.create_session()
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
        affects = flaw.affects
        results = list()
        product_versions = set()
        product_streams = set()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            for affect in affects:
                futures.append(
                    executor.submit(
                        self.corgi_session.components.retrieve_list,
                        name=affect.ps_component,
                        view="latest",
                    )
                )
            for future in concurrent.futures.as_completed(futures):
                try:
                    for c in future.result().results:
                        results.append(c.to_dict())
                except Exception as exc:
                    logger.error("%r generated an exception: %s" % (future, exc))
                    exit(0)

            for c in results:
                product_streams.add(c["product_stream"])
                product_versions.add(c["product_version"])
        return {
            "link": f"{OSIDB_API_URL}/osidb/api/v1/flaws/{flaw.cve_id}",
            "cve_id": flaw.cve_id,
            "title": flaw.title,
            "description": flaw.description,
            "product_versions": sorted(list(product_versions)),
            "product_streams": sorted(list(product_streams)),
            # "components": results,
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
        "search_latest",
        "search_all",
        "search_related_url",
        "search_community",
        "search_upstreams",
        "filter_rh_naming",
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
        "search_latest",
        "search_all",
        "search_related_url",
        "search_redhat",
        "search_community",
        "search_upstreams",
        "filter_rh_naming",
    ]

    def __init__(self, params: dict) -> None:
        self.corgi_session = CorgiService.create_session()
        self.params = params
        self.component_name = self.params.get("component_name")
        self.component_type = self.params.get("component_type")
        self.strict_name_search = self.params.get("strict_name_search")
        self.search_deps = self.params.get("search_deps")
        self.ns = self.params.get("namespace")
        self.search_latest = self.params.get("search_latest")
        self.search_all = self.params.get("search_all")
        self.search_related_url = self.params.get("search_related_url")
        self.search_redhat = self.params.get("search_redhat")
        self.search_community = self.params.get("search_community")
        self.search_upstreams = self.params.get("search_upstreams")
        self.filter_rh_naming = self.params.get("filter_rh_naming")

    def execute(self) -> List[Dict[str, Any]]:
        results = []
        if self.search_latest:
            cond = {"view": "latest"}
            if not self.strict_name_search:
                cond["re_name"] = self.component_name  # type: ignore
            else:
                cond["name"] = self.component_name  # type: ignore
            cond["namespace"] = "REDHAT"
            result = self.corgi_session.components.retrieve_list(**cond)
            results = result.results
            # TODO: this should be done server side at some point
            if self.component_type:
                results = [result for result in results if result.type == self.component_type]

        if self.search_community or self.search_related_url:
            # Note: related_url filter has no concept of strict
            params = {
                "include_fields": "name,arch,release,version,nvr,type,link,software_build,product_versions,product_streams,sources,upstreams,namespace,purl",  # noqa
                "arch": "src",
                "related_url": self.component_name,
            }
            params["namespace"] = "REDHAT"
            if self.component_type:
                params["type"] = self.component_type

            component_cnt = self.corgi_session.components.retrieve_list(**params).count
            if component_cnt < 3000000:
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    futures = []
                    components = list()
                    for batch in range(0, component_cnt, 120):
                        futures.append(
                            executor.submit(
                                self.corgi_session.components.retrieve_list,
                                **params,
                                offset=batch,
                                limit=120,  # noqa
                            )
                        )
                    params["arch"] = "noarch"
                    component_cnt = self.corgi_session.components.retrieve_list(**params).count
                    for batch in range(0, component_cnt, 120):
                        futures.append(
                            executor.submit(
                                self.corgi_session.components.retrieve_list,
                                **params,
                                offset=batch,
                                limit=120,  # noqa
                            )
                        )

                    for future in concurrent.futures.as_completed(futures):
                        try:
                            components.extend(future.result().results)
                        except Exception as exc:
                            logger.warning("%r generated an exception: %s" % (future, exc))

                    for c in components:
                        if self.strict_name_search:
                            if c.name != self.component_name:
                                continue
                        for pv in c.product_versions:
                            for ps in c.product_streams:
                                is_dep = False
                                if c.arch == "src" or c.arch == "noarch":
                                    is_dep = True
                                sources = [{"purl": source["purl"]} for source in c.sources]
                                component = {
                                    "is_dep": is_dep,
                                    "product_version": pv["name"],
                                    "product_version_ofuri": pv["ofuri"],
                                    "product_stream": ps["name"],
                                    "product_stream_ofuri": ps["ofuri"],
                                    "product_active": True,
                                    "purl": c.purl,
                                    "type": str(c.type),
                                    "namespace": str(c.namespace),
                                    "name": c.name,
                                    "arch": c.arch,
                                    "release": c.release,
                                    "version": c.version,
                                    "sources": sources,
                                    "nvr": c.nvr,
                                    "build_id": None,
                                    "build_type": None,
                                    "build_source_url": None,
                                    "related_url": None,
                                    "upstream_purl": None,
                                }
                                if c.software_build:
                                    component["build_id"] = c.software_build.build_id
                                    component["build_type"] = str(c.software_build.build_type)
                                    component["build_name"] = c.software_build.name
                                    component["build_source_url"] = c.software_build.source
                                if c.upstreams:
                                    component["upstream_purl"] = c.upstreams[0]["purl"]
                                results.append(component)

        if self.search_all:
            params = {
                "include_fields": "name,arch,release,version,nvr,type,link,software_build,product_versions,product_streams,sources,upstreams,namespace,purl",  # noqa
                "arch": "src",
            }
            if not self.strict_name_search:
                params["re_name"] = self.component_name
            else:
                params["name"] = self.component_name

            if self.component_type:
                params["type"] = self.component_type

            component_cnt = self.corgi_session.components.retrieve_list(**params).count
            if component_cnt < 3000000:
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    futures = []
                    components = list()
                    for batch in range(0, component_cnt, 100):
                        futures.append(
                            executor.submit(
                                self.corgi_session.components.retrieve_list,
                                **params,
                                offset=batch,
                                limit=100,  # noqa
                            )
                        )
                    params["arch"] = "noarch"
                    component_cnt = self.corgi_session.components.retrieve_list(**params).count
                    for batch in range(0, component_cnt, 120):
                        futures.append(
                            executor.submit(
                                self.corgi_session.components.retrieve_list,
                                **params,
                                offset=batch,
                                limit=120,  # noqa
                            )
                        )
                    for future in concurrent.futures.as_completed(futures):
                        try:
                            components.extend(future.result().results)
                        except Exception as exc:
                            logger.warning("%r generated an exception: %s" % (future, exc))

                    for c in components:
                        for pv in c.product_versions:
                            for ps in c.product_streams:
                                is_dep = False
                                if c.arch == "src" or c.arch == "noarch":
                                    is_dep = True
                                sources = [{"purl": source["purl"]} for source in c.sources]
                                component = {
                                    "is_dep": is_dep,
                                    "product_version": pv["name"],
                                    "product_version_ofuri": pv["ofuri"],
                                    "product_stream": ps["name"],
                                    "product_stream_ofuri": ps["ofuri"],
                                    "product_active": True,
                                    "purl": c.purl,
                                    "type": str(c.type),
                                    "namespace": str(c.namespace),
                                    "name": c.name,
                                    "arch": c.arch,
                                    "release": c.release,
                                    "version": c.version,
                                    "sources": sources,
                                    "nvr": c.nvr,
                                    "build_id": None,
                                    "build_type": None,
                                    "build_source_url": None,
                                    "related_url": None,
                                    "upstream_purl": None,
                                }
                                if c.software_build:
                                    component["build_id"] = c.software_build.build_id
                                    component["build_type"] = str(c.software_build.build_type)
                                    component["build_name"] = c.software_build.name
                                    component["build_source_url"] = c.software_build.source
                                if c.upstreams:
                                    component["upstream_purl"] = c.upstreams[0]["purl"]
                                results.append(component)

        if self.search_upstreams:
            # Note: upstreams only takes a purl ... so we must use re_upstreams for
            # both strict and not strict search
            params = params = {
                "include_fields": "name,arch,release,version,nvr,type,link,software_build,product_versions,product_streams,sources,upstreams,namespace,purl",  # noqa
                "arch": "src",
                "re_upstreams": self.component_name,
            }
            if self.component_type:
                params["type"] = self.component_type

            component_cnt = self.corgi_session.components.retrieve_list(**params).count
            if component_cnt < 3000000:
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    # search src and noarch
                    futures = []
                    components = list()
                    for batch in range(0, component_cnt, 120):
                        futures.append(
                            executor.submit(
                                self.corgi_session.components.retrieve_list,
                                **params,
                                offset=batch,
                                limit=120,  # noqa
                            )
                        )
                    params["arch"] = "noarch"
                    component_cnt = self.corgi_session.components.retrieve_list(**params).count
                    for batch in range(0, component_cnt, 120):
                        futures.append(
                            executor.submit(
                                self.corgi_session.components.retrieve_list,
                                **params,
                                offset=batch,
                                limit=120,  # noqa
                            )
                        )

                    for future in concurrent.futures.as_completed(futures):
                        try:
                            components.extend(future.result().results)
                        except Exception as exc:
                            logger.warning("%r generated an exception: %s" % (future, exc))

                    for c in components:
                        if self.strict_name_search:
                            if c.name != self.component_name:
                                continue
                        for pv in c.product_versions:
                            for ps in c.product_streams:
                                is_dep = False
                                if c.arch == "src" or c.arch == "noarch":
                                    is_dep = True
                                sources = [{"purl": source["purl"]} for source in c.sources]
                                component = {
                                    "is_dep": is_dep,
                                    "product_version": pv["name"],
                                    "product_version_ofuri": pv["ofuri"],
                                    "product_stream": ps["name"],
                                    "product_stream_ofuri": ps["ofuri"],
                                    "product_active": True,
                                    "purl": c.purl,
                                    "type": str(c.type),
                                    "namespace": str(c.namespace),
                                    "name": c.name,
                                    "arch": c.arch,
                                    "release": c.release,
                                    "version": c.version,
                                    "sources": sources,
                                    "nvr": c.nvr,
                                    "build_id": None,
                                    "build_type": None,
                                    "build_source_url": None,
                                    "related_url": None,
                                    "upstream_purl": None,
                                }
                                if c.software_build:
                                    component["build_id"] = c.software_build.build_id
                                    component["build_type"] = str(c.software_build.build_type)
                                    component["build_name"] = c.software_build.name
                                    component["build_source_url"] = c.software_build.source
                                if c.upstreams:
                                    component["upstream_purl"] = c.upstreams[0]["purl"]
                                results.append(component)

        if self.filter_rh_naming:
            flags = re.IGNORECASE
            patterns = [
                # binutils
                re.compile(
                    f"(devtoolset\\-[0-9]+\\-|mingw\\-|gcc\\-toolset\\-[0-9]+\\-)?{self.component_name}[0-9\\.]*$",  # noqa
                    flags=flags,
                ),
                # compat-* style
                re.compile(f"(compat\\-)?{self.component_name}[0-9\\.]*(\\-[0-9]+)?$", flags=flags),
                # kernel
                re.compile(f"^{self.component_name}(\\-rt)?$", flags=flags),
                # qemu
                re.compile(f"^{self.component_name}(\\-kvm(\\-rhev|\\-ma)?)?$", flags=flags),
                # webkit
                re.compile(f"^{self.component_name}([0-9])?(gtk)?([0-9])?$", flags=flags),
            ]

            filtered_results = []
            for result in results:
                is_matched = False
                for p in patterns:
                    if is_matched:
                        break
                    if type(result) == Component:
                        m = p.match(result.name)
                        if m:
                            filtered_results.append(result)
                            is_matched = True
                            break
                    else:
                        m = p.match(result["name"])
                        if m:
                            filtered_results.append(result)
                            is_matched = True
                            break

            results = filtered_results

        if self.search_community or self.search_all:
            self.community_session = CommunityComponentService.create_session()

            params = {
                "include_fields": "name,arch,release,version,nvr,type,link,software_build,product_versions,product_streams,sources,upstreams,namespace,purl",  # noqa
                "arch": "src",
            }
            if not self.strict_name_search:
                params["re_name"] = self.component_name
            else:
                params["name"] = self.component_name

            if self.component_type:
                params["type"] = self.component_type

            component_cnt = self.community_session.components.retrieve_list(**params).count
            if component_cnt < 3000000:
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    futures = []
                    components = list()
                    for batch in range(0, component_cnt, 100):
                        futures.append(
                            executor.submit(
                                self.community_session.components.retrieve_list,
                                **params,
                                offset=batch,
                                limit=100,  # noqa
                            )
                        )
                    params["arch"] = "noarch"
                    component_cnt = self.corgi_session.components.retrieve_list(**params).count
                    for batch in range(0, component_cnt, 120):
                        futures.append(
                            executor.submit(
                                self.community_session.components.retrieve_list,
                                **params,
                                offset=batch,
                                limit=120,  # noqa
                            )
                        )
                    for future in concurrent.futures.as_completed(futures):
                        try:
                            components.extend(future.result().results)
                        except Exception as exc:
                            logger.warning("%r generated an exception: %s" % (future, exc))

                    for c in components:
                        for pv in c.product_versions:
                            for ps in c.product_streams:
                                is_dep = False
                                if c.arch == "src" or c.arch == "noarch":
                                    is_dep = True
                                sources = [{"purl": source["purl"]} for source in c.sources]
                                component = {
                                    "is_dep": is_dep,
                                    "product_version": pv["name"],
                                    "product_version_ofuri": pv["ofuri"],
                                    "product_stream": ps["name"],
                                    "product_stream_ofuri": ps["ofuri"],
                                    "product_active": True,
                                    "purl": c.purl,
                                    "type": str(c.type),
                                    "namespace": str(c.namespace),
                                    "name": c.name,
                                    "arch": c.arch,
                                    "release": c.release,
                                    "version": c.version,
                                    "sources": sources,
                                    "nvr": c.nvr,
                                    "build_id": None,
                                    "build_type": None,
                                    "build_source_url": None,
                                    "related_url": None,
                                    "upstream_purl": None,
                                }
                                if c.software_build:
                                    component["build_id"] = c.software_build.build_id
                                    component["build_type"] = str(c.software_build.build_type)
                                    component["build_name"] = c.software_build.name
                                    component["build_source_url"] = c.software_build.source
                                if c.upstreams:
                                    component["upstream_purl"] = c.upstreams[0]["purl"]
                                results.append(component)

        return results


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
                            include_fields="link,name,type,arch,version,purl,nvr,sources,related_url,download_url",  # noqa
                            limit=120,
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
                    "nvr": c.nvr,
                    "arch": c.arch,
                    "download_url": c.download_url,
                    "related_url": c.related_url,
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
        affects = flaw.affects
        results = list()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            for affect in affects:
                futures.append(
                    executor.submit(
                        self.corgi_session.components.retrieve_list,
                        name=affect.ps_component,
                        view="latest",
                    )
                )
            for future in concurrent.futures.as_completed(futures):
                try:
                    for c in future.result().results:
                        results.append(c.to_dict())
                except Exception as exc:
                    logger.error("%r generated an exception: %s" % (future, exc))
                    exit(0)

        return {
            "link": f"{OSIDB_API_URL}/osidb/api/v1/flaws/{flaw.cve_id}",
            "cve_id": flaw.cve_id,
            "title": flaw.title,
            "description": flaw.description,
            "components": results,
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
            params = {
                "include_fields": "cve_id,title,state,resolution,impact,affects",
            }
            params["affects__ps_component"] = self.component_name
            if self.flaw_state:
                params["state"] = self.flaw_state
            if self.flaw_resolution:
                params["resolution"] = self.flaw_resolution
            if self.flaw_impact:
                params["impact"] = self.flaw_impact
            if self.affectedness:
                params["affects__affectedness"] = self.affectedness
            if self.affect_resolution:
                params["affects__resolution"] = self.affect_resolution
            if self.affect_impact:
                params["affects__impact"] = self.affect_impact

            res = requests.get(f"{OSIDB_API_URL}/osidb/api/v1/flaws", params=params)
            flaws = res.json()
            flaws_cnt = int(flaws["count"])
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = []
                flaws = list()
                for batch in range(0, flaws_cnt, 75):
                    params["offset"] = batch  # type: ignore
                    params["limit"] = 75  # type: ignore
                    futures.append(
                        executor.submit(
                            requests.get,
                            f"{OSIDB_API_URL}/osidb/api/v1/flaws",
                            params=params,
                        )
                    )
                for future in concurrent.futures.as_completed(futures):
                    try:
                        flaws.extend(future.result().json()["results"])
                    except Exception as exc:
                        logger.warning("%r generated an exception: %s" % (future, exc))

                for flaw in flaws:
                    for affect in flaw["affects"]:
                        if self.affectedness:
                            if self.affectedness != affect["affectedness"]:
                                continue
                        if self.affect_resolution:
                            if self.affect_resolution != affect["resolution"]:
                                continue
                        if self.affect_impact:
                            if self.affect_impact != affect["impact"]:
                                continue
                        affects.append(
                            {
                                "link_affect": f"{OSIDB_API_URL}/osidb/api/v1/affects/{affect['uuid']}",  # noqa
                                "link_cve": f"{OSIDB_API_URL}/osidb/api/v1/flaws/{flaw['cve_id']}",  # noqa
                                "link_component": f"{CORGI_API_URL}/api/v1/components?name={affect['ps_component']}&view=latest",  # noqa
                                "link_community_component": f"{COMMUNITY_COMPONENTS_API_URL}/api/v1/components?name={affect['ps_component']}&view=latest",  # noqa
                                "flaw_cve_id": flaw["cve_id"],
                                "title": flaw["title"],
                                "flaw_state": flaw["state"],
                                "flaw_resolution": flaw["resolution"],
                                "affect_component_name": affect["ps_component"],
                                "affect_product_version": affect["ps_module"],
                                "affect_affectedness": affect["affectedness"],
                                "affect_impact": affect["impact"],
                                "affect_resolution": affect["resolution"],
                            }
                        )
                components.append(
                    {
                        "link": f"{CORGI_API_URL}/api/v1/components?name={self.component_name}",
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
            params = {
                "include_fields": "cve_id,title,state,resolution,impact,affects",
            }
            params["affects__ps_module"] = self.product_version_name
            if self.flaw_state:
                params["state"] = self.flaw_state
            if self.flaw_resolution:
                params["resolution"] = self.flaw_resolution
            if self.flaw_impact:
                params["impact"] = self.flaw_impact
            if self.affectedness:
                params["affects__affectedness"] = self.affectedness
            if self.affect_resolution:
                params["affects__resolution"] = self.affect_resolution
            if self.affect_impact:
                params["affects__impact"] = self.affect_impact

            res = requests.get(f"{OSIDB_API_URL}/osidb/api/v1/flaws", params=params)
            flaws = res.json()
            flaws_cnt = int(flaws["count"])
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = []
                flaws = list()
                for batch in range(0, flaws_cnt, 75):
                    params["offset"] = batch  # type: ignore
                    params["limit"] = 75  # type: ignore
                    futures.append(
                        executor.submit(
                            requests.get,
                            f"{OSIDB_API_URL}/osidb/api/v1/flaws",
                            params=params,
                        )
                    )
                for future in concurrent.futures.as_completed(futures):
                    try:
                        flaws.extend(future.result().json()["results"])
                    except Exception as exc:
                        logger.warning("%r generated an exception: %s" % (future, exc))

                for flaw in flaws:
                    for affect in flaw["affects"]:
                        if self.affectedness:
                            if self.affectedness != affect["affectedness"]:
                                continue
                        if self.affect_resolution:
                            if self.affect_resolution != affect["resolution"]:
                                continue
                        if self.affect_impact:
                            if self.affect_impact != affect["impact"]:
                                continue
                        affects.append(
                            {
                                "link_affect": f"{OSIDB_API_URL}/osidb/api/v1/affects/{affect['uuid']}",  # noqa
                                "link_cve": f"{OSIDB_API_URL}/osidb/api/v1/flaws/{flaw['cve_id']}",  # noqa
                                "link_component": f"{CORGI_API_URL}/api/v1/components?name={affect['ps_component']}&view=latest",  # noqa
                                "link_community_component": f"{COMMUNITY_COMPONENTS_API_URL}/api/v1/components?name={affect['ps_component']}&view=latest",  # noqa
                                "flaw_cve_id": flaw["cve_id"],
                                "title": flaw["title"],
                                "flaw_state": flaw["state"],
                                "flaw_resolution": flaw["resolution"],
                                "affect_component_name": affect["ps_component"],
                                "affect_product_version": affect["ps_module"],
                                "affect_affectedness": affect["affectedness"],
                                "affect_impact": affect["impact"],
                                "affect_resolution": affect["resolution"],
                            }
                        )
                components.append(
                    {
                        "link": f"{CORGI_API_URL}/api/v1/product_versions?name={self.product_version_name}",  # noqa
                        "name": self.product_version_name,
                        "affects": affects,
                    }
                )

        return components
