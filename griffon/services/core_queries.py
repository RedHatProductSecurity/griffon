"""
    read only queries

"""
import copy
import logging
import multiprocessing
import re
from functools import partial
from typing import Any, Dict, List

from component_registry_bindings.bindings.python_client.models import Component

from griffon import (
    COMMUNITY_COMPONENTS_SERVER_URL,
    CORGI_SERVER_URL,
    OSIDB_SERVER_URL,
    CommunityComponentService,
    CorgiService,
    OSIDBService,
)

logger = logging.getLogger("griffon")

ITEM_BATCH = 75


class product_stream_summary:
    """retrieve product_stream summary"""

    name = "product_stream_summary"
    description = "retrieve product_stream summary"
    allowed_params = [
        "strict_name_search",
        "all",
        "product_stream_name",
        "ofuri",
        "verbose",
        "regex_name_search",
    ]

    def __init__(self, params: dict) -> None:
        self.corgi_session = CorgiService.create_session()
        self.params = params
        self.product_stream_name = self.params.get("product_stream_name")
        self.ofuri = self.params.get("ofuri")
        self.strict_name_search = self.params.get("strict_name_search", None)
        self.all = self.params.get("all", None)
        self.regex_name_search = self.params.get("regex_name_search")

    def execute(self, status=None) -> List[Dict[str, Any]]:
        cond = {}

        product_stream_name = (
            re.escape(self.product_stream_name)
            if not self.regex_name_search
            else self.product_stream_name
        )

        if self.ofuri:
            cond["ofuri"] = self.ofuri
        elif not self.strict_name_search:
            if not self.all:
                cond["re_name"] = product_stream_name
        else:
            if not self.all:
                cond["name"] = product_stream_name

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
                    "product_version": str([pv["name"] for pv in ps.product_versions]),
                    "brew_tags": [brew_tag for brew_tag in ps.brew_tags.to_dict().keys()],
                    # "build_count": ps.build_count,
                    "manifest_link": ps.manifest,
                    "latest_components_link": f"{CORGI_SERVER_URL}/api/v1/components?ofuri={ps.ofuri}&view=summary",  # noqa
                    "all_components_link": f"{CORGI_SERVER_URL}/api/v1/components?product_streams={ps.ofuri}&include_fields=link,name,purl",  # noqa
                }
                results.append(result)
        else:
            if "ofuri" in product_streams:
                result = {
                    "link": product_streams["link"],
                    "ofuri": product_streams["ofuri"],
                    "name": product_streams["name"],
                    "product": product_streams["products"][0]["name"],
                    "product_version": product_streams["product_versions"][0]["name"],
                    "brew_tags": "",
                    "manifest_link": product_streams["manifest"],
                    "latest_components_link": f"{CORGI_SERVER_URL}/api/v1/components?ofuri={product_streams['ofuri']}&view=summary",  # noqa
                    "all_components_link": f"{CORGI_SERVER_URL}/api/v1/components?product_streams={product_streams['ofuri']}&include_fields=link,name,purl",  # noqa
                }
                results.append(result)
            else:
                logger.warning("No such product stream")
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

    def execute(self, status=None) -> dict:
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
        for affect in affects:
            components = self.corgi_session.components.retrieve_list_iterator_async(
                name=affect.ps_component,
                latest_components_by_streams="True",
                include_fields="product_streams.name,product_versions.name",
            )
            for c in components:
                results.append(c.to_dict())
        for c in results:
            for ps in c["product_streams"]:
                product_streams.add(ps["name"])
            for pv in c["product_versions"]:
                product_versions.add(ps["name"])
        return {
            "link": f"{OSIDB_SERVER_URL}/osidb/api/v1/flaws/{flaw.cve_id}",
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
        "search_provides",
        "search_upstreams",
        "search_all",
        "search_all_roots",
        "search_all_upstreams",
        "search_related_url",
        "search_community",
        "search_upstreams",
        "filter_rh_naming",
        "no_community",
        "no_middleware",
        "no_upstream_affects",
        "include_inactive_product_streams",
        "include_product_stream_excluded_components",
        "output_type_filter",
        "regex_name_search",
        "include_container_roots",
        "exclude_unreleased",
    ]

    def __init__(self, params: dict) -> None:
        self.corgi_session = CorgiService.create_session()
        self.params = params
        self.purl = self.params.get("purl")

    def execute(self, status=None) -> dict:
        c = self.corgi_session.components.retrieve_list(
            purl=self.purl,
        )
        return c["product_streams"]


def async_retrieve_sources(self, purl):
    params = {
        "limit": ITEM_BATCH,
        "root_components": "True",
        "provides": purl,
        "include_fields": "type,arch,nvr,purl,name,version,namespace",
    }
    try:
        return list(self.components.retrieve_list_iterator_async(**params))
    except Exception as e:
        logger.warning(f"{type(e).__name__} - problem retrieving {purl} sources.")
        return []


def async_retrieve_upstreams(self, purl):
    params = {
        "limit": ITEM_BATCH,
        "root_components": "True",
        "upstreams": purl,
        "include_fields": "type,arch,nvr,purl,name,version,namespace",
    }
    try:
        return list(self.components.retrieve_list_iterator_async(**params, max_results=5000))
    except Exception as e:
        logger.warning(f"{type(e).__name__} - problem retrieving {purl} upstreams.")
        return []


def async_retrieve_provides(self, urlparams, purl):
    params = {
        "limit": ITEM_BATCH,
        "sources": purl,
        "include_fields": "type,arch,nvr,purl,version,name,namespace",
    }
    if "name" in urlparams:
        params["name"] = urlparams["name"]
    if "provides_name" in urlparams:
        params["name"] = urlparams["provides_name"]
    if "re_name" in urlparams:
        params["re_name"] = urlparams["re_name"]
    if "re_provides_name" in urlparams:
        params["re_name"] = urlparams["re_provides_name"]
    if "namespace" in urlparams:
        params["namespace"] = urlparams["namespace"]
    try:
        return list(self.components.retrieve_list_iterator_async(**params, max_results=5000))
    except Exception as e:
        logger.warning(f"{type(e).__name__} - problem retrieving {purl} provides.")
        return []


def process_component(session, urlparams, c):
    """perform any neccessary sub retrievals."""
    c.sources = async_retrieve_sources(session, c.purl)
    c.upstreams = async_retrieve_upstreams(session, c.purl)
    c.provides = async_retrieve_provides(session, urlparams, c.purl)
    return c


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
        "search_provides",
        "search_upstreams",
        "search_all",
        "search_all_roots",
        "search_all_upstreams",
        "search_related_url",
        "search_community",
        "search_upstreams",
        "filter_rh_naming",
        "no_community",
        "no_middleware",
        "no_upstream_affects",
        "include_inactive_product_streams",
        "include_product_stream_excluded_components",
        "output_type_filter",
        "regex_name_search",
        "include_container_roots",
        "exclude_unreleased",
    ]

    def __init__(self, params: dict) -> None:
        self.corgi_session = CorgiService.create_session()
        self.params = params
        self.component_name = self.params.get("component_name", "")
        self.component_type = self.params.get("component_type", "")
        self.strict_name_search = self.params.get("strict_name_search")
        self.search_deps = self.params.get("search_deps")
        self.ns = self.params.get("namespace")
        self.search_latest = self.params.get("search_latest")
        self.search_all = self.params.get("search_all")
        self.search_all_roots = self.params.get("search_all_roots")
        self.search_related_url = self.params.get("search_related_url")
        self.search_community = self.params.get("search_community")
        self.search_all_upstreams = self.params.get("search_all_upstreams")
        self.filter_rh_naming = self.params.get("filter_rh_naming")
        self.no_community = self.params.get("no_community")
        self.search_provides = self.params.get("search_provides")
        self.search_upstreams = self.params.get("search_upstreams")
        self.regex_name_search = self.params.get("regex_name_search")
        if not self.no_community:
            self.community_session = CommunityComponentService.create_session()
        self.include_inactive_product_streams = self.params.get("include_inactive_product_streams")
        self.include_container_roots = self.params.get("include_container_roots")
        self.exclude_unreleased = self.params.get("exclude_unreleased")

    def execute(self, status=None) -> List[Dict[str, Any]]:
        status.update("searching component-registry.")
        results = []
        params = {
            "limit": ITEM_BATCH,
            "include_fields": "purl,type,name,related_url,namespace,software_build,nvr,release,version,arch,product_streams.product_versions,product_streams.name,product_streams.ofuri,product_streams.active,product_streams.exclude_components,product_streams.relations",  # noqa
        }
        if not (self.include_inactive_product_streams):
            params["active_streams"] = "True"
        if self.exclude_unreleased:
            params["released_components"] = "True"
        if not (self.include_container_roots):
            params["type"] = "RPM"
        if self.ns:
            params["namespace"] = self.ns
        if self.component_type:
            params["type"] = self.component_type

        component_name = self.component_name
        if not self.strict_name_search and not self.regex_name_search:
            component_name = re.escape(component_name)

        if self.search_provides:
            search_provides_params = copy.deepcopy(params)
            if not (self.strict_name_search):
                search_provides_params["re_provides_name"] = component_name
            else:
                search_provides_params["provides_name"] = component_name
            search_provides_params["latest_components_by_streams"] = "True"
            status.update("searching latest provided child component(s).")
            latest_components_cnt = self.corgi_session.components.count(**search_provides_params)
            status.update(f"found {latest_components_cnt} latest provides component(s).")
            latest_components = self.corgi_session.components.retrieve_list_iterator_async(
                **search_provides_params, max_results=10000
            )

            status.update(
                f"found {latest_components_cnt} latest provides child component(s)- retrieving children, sources & upstreams."  # noqa
            )
            with multiprocessing.Pool() as pool:
                for processed_component in pool.map(
                    partial(process_component, self.corgi_session, search_provides_params),
                    latest_components,
                ):
                    results.append(processed_component)
            # if we have found no children then search_latest for roots
            if not (results):
                self.search_latest = True

            if not self.no_community:
                status.update("searching latest community provided child component(s).")
                community_component_cnt = self.community_session.components.count(
                    **search_provides_params
                )
                status.update(
                    f"found {community_component_cnt} latest community provided child component(s)."  # noqa
                )
                latest_community_components = (
                    self.community_session.components.retrieve_list_iterator_async(
                        **search_provides_params, max_results=10000
                    )
                )
                status.update(
                    f"found {community_component_cnt} latest community provided child component(s)- retrieving children, sources & upstreams."  # noqa
                )
                with multiprocessing.Pool() as pool:
                    for processed_component in pool.map(
                        partial(process_component, self.community_session, search_provides_params),
                        latest_community_components,
                    ):
                        results.append(processed_component)

        if self.search_latest:
            search_latest_params = copy.deepcopy(params)
            if not (self.strict_name_search):
                search_latest_params["re_name"] = component_name
            else:
                search_latest_params["name"] = component_name
            search_latest_params["root_components"] = "True"
            search_latest_params["latest_components_by_streams"] = "True"
            status.update("searching latest root component(s).")
            latest_components_cnt = self.corgi_session.components.count(**search_latest_params)
            status.update(f"found {latest_components_cnt} latest component(s).")
            latest_components = self.corgi_session.components.retrieve_list_iterator_async(
                **search_latest_params, max_results=10000
            )
            status.update(f"found {latest_components_cnt} latest root component(s).")  # noqa
            with multiprocessing.Pool() as pool:
                for processed_component in pool.map(
                    partial(process_component, self.corgi_session, search_latest_params),
                    latest_components,
                ):
                    results.append(processed_component)

            if not self.no_community:
                status.update("searching latest community root component(s).")
                community_component_cnt = self.community_session.components.count(
                    **search_latest_params
                )
                status.update(
                    f"found {community_component_cnt} latest community root component(s)."  # noqa
                )
                latest_community_components = (
                    self.community_session.components.retrieve_list_iterator_async(
                        **search_latest_params, max_results=10000
                    )
                )
                status.update(
                    f"found {community_component_cnt} latest community root component(s)- retrieving children, sources & upstreams."  # noqa
                )
                with multiprocessing.Pool() as pool:
                    for processed_component in pool.map(
                        partial(process_component, self.community_session, search_latest_params),
                        latest_community_components,
                    ):
                        results.append(processed_component)

        if self.search_upstreams:
            search_upstreams_params = copy.deepcopy(params)
            search_upstreams_params["latest_components_by_streams"] = "True"
            if not (self.strict_name_search):
                search_upstreams_params["re_upstreams_name"] = component_name
            else:
                search_upstreams_params["upstreams_name"] = component_name
            search_upstreams_params["latest_components_by_streams"] = "True"
            status.update("searching latest upstreams child component(s).")
            latest_components_cnt = self.corgi_session.components.count(**search_upstreams_params)
            status.update(f"found {latest_components_cnt} latest component(s).")
            latest_components = self.corgi_session.components.retrieve_list_iterator_async(
                **search_upstreams_params, max_results=10000
            )
            with multiprocessing.Pool() as pool:
                status.update(
                    f"found {latest_components_cnt} latest upstreams child component(s)- retrieving children, sources & upstreams."  # noqa
                )
                for processed_component in pool.map(
                    partial(process_component, self.corgi_session, search_upstreams_params),
                    latest_components,
                ):
                    results.append(processed_component)
            if not self.no_community:
                status.update("searching latest community upstreams child component(s).")
                community_component_cnt = self.community_session.components.count(
                    **search_upstreams_params
                )
                status.update(
                    f"found {community_component_cnt} latest community upstreams child component(s)."  # noqa
                )
                latest_community_components = (
                    self.community_session.components.retrieve_list_iterator_async(
                        **search_upstreams_params, max_results=10000
                    )
                )
                with multiprocessing.Pool() as pool:
                    status.update(
                        f"found {community_component_cnt} latest community provided child component(s)- retrieving children, sources & upstreams."  # noqa
                    )
                    for processed_component in pool.map(
                        partial(process_component, self.community_session, search_upstreams_params),
                        latest_community_components,
                    ):
                        results.append(processed_component)

        if self.search_related_url:
            search_related_url_params = copy.deepcopy(params)
            # Note: related_url filter has no concept of strict
            search_related_url_params["related_url"] = component_name
            related_url_components_cnt = self.corgi_session.components.count(
                **search_related_url_params,
            )
            status.update(f"found {related_url_components_cnt} related url component(s).")
            related_url_components = self.corgi_session.components.retrieve_list_iterator_async(
                **search_related_url_params, max_results=10000
            )
            for c in related_url_components:
                results.append(c)

            if not self.no_community:
                latest_community_url_components_cnt = self.community_session.components.count(
                    **search_related_url_params
                )
                status.update(
                    f"found {latest_community_url_components_cnt} related url community component(s)."  # noqa
                )
                latest_community_url_components = (
                    self.community_session.components.retrieve_list_iterator_async(
                        **search_related_url_params, max_results=10000
                    )
                )
                for c in latest_community_url_components:
                    results.append(c)

        if self.search_all:
            search_all_params = copy.deepcopy(params)
            if not (self.strict_name_search):
                search_all_params["re_name"] = component_name
            else:
                search_all_params["name"] = component_name
            all_components_cnt = self.corgi_session.components.count(**search_all_params)
            status.update(f"found {all_components_cnt} all component(s).")
            # TODO: remove max_results
            all_components = self.corgi_session.components.retrieve_list_iterator_async(
                **search_all_params, max_results=10000
            )
            status.update(f"found {all_components_cnt} all component(s).")
            for c in all_components:
                c.upstreams = []
                c.sources = []
                results.append(c)

            if not self.no_community:
                all_community_components_cnt = self.community_session.components.count(
                    **search_all_params
                )
                status.update(
                    f"found {all_community_components_cnt} community all component(s)."  # noqa
                )
                # TODO: remove max_results
                all_community_components = (
                    self.community_session.components.retrieve_list_iterator_async(
                        **search_all_params, max_results=10000
                    )
                )
                for c in all_community_components:
                    c.upstreams = []
                    c.sources = []
                    results.append(c)

        if self.search_all_roots:
            search_all_roots_params = copy.deepcopy(params)
            search_all_roots_params["root_components"] = "True"
            if not (self.strict_name_search):
                search_all_roots_params["re_name"] = component_name
            else:
                search_all_roots_params["name"] = component_name
            all_src_components_cnt = self.corgi_session.components.count(**search_all_roots_params)
            status.update(f"found {all_src_components_cnt} all root component(s).")
            all_src_components = self.corgi_session.components.retrieve_list_iterator_async(
                **search_all_roots_params, max_results=10000
            )
            for c in all_src_components:
                c.upstreams = []
                c.sources = []
                results.append(c)
            if not self.no_community:
                all_src_community_components_cnt = self.community_session.components.count(
                    **search_all_roots_params
                )
                all_src_community_components = (
                    self.community_session.components.retrieve_list_iterator_async(
                        **search_all_roots_params, max_results=10000
                    )
                )
                status.update(
                    f"found {all_src_community_components_cnt} community all root component(s)."  # noqa
                )
                for c in all_src_community_components:
                    c.upstreams = []
                    c.sources = []
                    results.append(c)

        if self.search_all_upstreams:
            search_all_upstreams_params = copy.deepcopy(params)
            search_all_upstreams_params["namespace"] = "UPSTREAM"
            if not (self.strict_name_search):
                search_all_upstreams_params["re_name"] = component_name
            else:
                search_all_upstreams_params["name"] = component_name
            upstream_components_cnt = self.corgi_session.components.count(
                **search_all_upstreams_params
            )
            status.update(f"found {upstream_components_cnt} upstream component(s).")
            upstream_components = self.corgi_session.components.retrieve_list_iterator_async(
                **search_all_upstreams_params, max_results=10000
            )
            with multiprocessing.Pool() as pool:
                status.update(f"found {upstream_components_cnt} upstream component(s).")
                for processed_component in pool.map(
                    partial(process_component, self.corgi_session, search_all_upstreams_params),
                    upstream_components,
                ):
                    results.append(processed_component)
            if not self.no_community:
                commmunity_upstream_components_cnt = self.community_session.components.count(
                    **search_all_upstreams_params
                )
                status.update(
                    f"found {commmunity_upstream_components_cnt} community upstream component(s)."  # noqa
                )
                commmunity_upstream_components = (
                    self.community_session.components.retrieve_list_iterator_async(
                        **search_all_upstreams_params, max_results=10000
                    )
                )
                with multiprocessing.Pool() as pool:
                    status.update(
                        f"found {commmunity_upstream_components_cnt} community upstream component(s)- retrieving children, sources & upstreams."  # noqa
                    )
                    for processed_component in pool.map(
                        partial(
                            process_component, self.community_session, search_all_upstreams_params
                        ),
                        commmunity_upstream_components,
                    ):
                        results.append(processed_component)

        if self.filter_rh_naming:
            flags = re.IGNORECASE
            patterns = [
                # binutils
                re.compile(
                    f"(devtoolset\\-[0-9]+\\-|mingw\\-|gcc\\-toolset\\-[0-9]+\\-)?{component_name}[0-9\\.]*$",  # noqa
                    flags=flags,
                ),
                # compat-* style
                re.compile(f"(compat\\-)?{component_name}[0-9\\.]*(\\-[0-9]+)?$", flags=flags),
                # kernel
                re.compile(f"^{component_name}(\\-rt)?$", flags=flags),
                # qemu
                re.compile(f"^{component_name}(\\-kvm(\\-rhev|\\-ma)?)?$", flags=flags),
                # webkit
                re.compile(f"^{component_name}([0-9])?(gtk)?([0-9])?$", flags=flags),
            ]

            filtered_results = []

            for result in results:
                is_matched = False
                for p in patterns:
                    if is_matched:
                        break
                    if type(result) == Component:
                        m = p.match(result.name)
                        logger.debug(f"rh naming filtered {result.name}")
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

        if self.search_community:
            search_community_params = copy.deepcopy(params)
            if not (self.strict_name_search):
                search_community_params["re_name"] = component_name
            else:
                search_community_params["name"] = component_name
            all_community_components_cnt = self.community_session.components.count(
                **search_community_params
            )
            status.update(
                f"found {all_community_components_cnt} community all component(s)."  # noqa
            )
            all_community_components = (
                self.community_session.components.retrieve_list_iterator_async(
                    **search_community_params
                )
            )
            with multiprocessing.Pool() as pool:
                status.update(
                    f"found {all_community_components_cnt} community all component(s)- retrieving children, sources & upstreams."  # noqa
                )
                for processed_component in pool.map(
                    partial(process_component, self.community_session, search_community_params),
                    all_community_components,
                ):
                    results.append(processed_component)

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
        "verbose",
        "regex_name_search",
    ]

    def __init__(self, params: dict):
        self.corgi_session = CorgiService.create_session()
        self.params = params
        self.purl = self.params.get("purl")

    def execute(self, status=None) -> dict:
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
        "verbose",
        "regex_name_search",
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
        self.regex_name_search = self.params.get("regex_name_search")

    def execute(self, status=None) -> List[Dict[str, Any]]:
        component_name = (
            re.escape(self.component_name) if not self.regex_name_search else self.component_name
        )

        cond = {"limit": ITEM_BATCH}
        if not self.strict_name_search:
            cond["re_name"] = component_name
        else:
            cond["name"] = component_name
        if self.component_version:
            cond["version"] = self.component_version
        if self.component_arch:
            cond["arch"] = self.component_arch
        if self.namespace:
            cond["namespace"] = self.namespace

        components = self.corgi_session.components.retrieve_list_iterator_async(**cond)
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

    def execute(self, status=None) -> dict:
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

        for affect in affects:
            components = self.corgi_session.components.retrieve_list_iterator_async(
                name=affect.ps_component,
                latest_components_by_streams="True",
                include_fields="purl,product_streams,product_versions,software_build",
            )
            for c in components:
                results.append(c.to_dict())

        return {
            "link": f"{OSIDB_SERVER_URL}/osidb/api/v1/flaws/{flaw.cve_id}",
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

    def execute(self, status=None) -> List[Dict[str, Any]]:
        components = []
        if self.component_name:
            affects: list = []
            params = {
                "include_fields": "cve_id,title,resolution,impact,affects",
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

            flaws = self.osidb_session.flaws.retrieve_list_iterator_async(**params)

            for flaw in flaws:
                for affect in flaw.affects:
                    if self.affectedness:
                        if self.affectedness != affect.affectedness:
                            continue
                    if self.affect_resolution:
                        if self.affect_resolution != affect.resolution:
                            continue
                    if self.affect_impact:
                        if self.affect_impact != affect.impact:
                            continue
                    affects.append(
                        {
                            "link_affect": f"{OSIDB_SERVER_URL}/osidb/api/v1/affects/{affect.uuid}",  # noqa
                            "link_cve": f"{OSIDB_SERVER_URL}/osidb/api/v1/flaws/{flaw.cve_id}",  # noqa
                            "link_component": f"{CORGI_SERVER_URL}/api/v1/components?name={affect.ps_component}&latest_components_by_streams=True",  # noqa
                            "link_community_component": f"{COMMUNITY_COMPONENTS_SERVER_URL}/api/v1/components?name={affect.ps_component}&latest_components_by_streams=True",  # noqa
                            "flaw_cve_id": flaw.cve_id,
                            "title": flaw.title,
                            "flaw_resolution": flaw.resolution,
                            "affect_component_name": affect.ps_component,
                            "affect_product_version": affect.ps_module,
                            "affect_affectedness": affect.affectedness,
                            "affect_impact": affect.impact,
                            "affect_resolution": affect.resolution,
                        }
                    )
            components.append(
                {
                    "link": f"{CORGI_SERVER_URL}/api/v1/components?name={self.component_name}",
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

    def execute(self, status=None) -> List[Dict[str, Any]]:
        components = []
        if self.product_version_name:
            affects: list = []
            params = {
                "include_fields": "cve_id,title,resolution,impact,affects",
            }
            params["affects__ps_module"] = self.product_version_name
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

            flaws = self.osidb_session.flaws.retrieve_list_iterator_async(**params)
            for flaw in flaws:
                for affect in flaw.affects:
                    if self.affectedness:
                        if self.affectedness != affect.affectedness:
                            continue
                    if self.affect_resolution:
                        if self.affect_resolution != affect.resolution:
                            continue
                    if self.affect_impact:
                        if self.affect_impact != affect.impact:
                            continue
                    affects.append(
                        {
                            "link_affect": f"{OSIDB_SERVER_URL}/osidb/api/v1/affects/{affect.uuid}",  # noqa
                            "link_cve": f"{OSIDB_SERVER_URL}/osidb/api/v1/flaws/{flaw.cve_id}",  # noqa
                            "link_component": f"{CORGI_SERVER_URL}/api/v1/components?name={affect.ps_component}&latest_components_by_streams=True",  # noqa
                            "link_community_component": f"{COMMUNITY_COMPONENTS_SERVER_URL}/api/v1/components?name={affect.ps_component}&latest_components_by_streams=True",  # noqa
                            "flaw_cve_id": flaw.cve_id,
                            "title": flaw.title,
                            "flaw_state": flaw.state,
                            "flaw_resolution": flaw.resolution,
                            "affect_component_name": affect.ps_component,
                            "affect_product_version": affect.ps_module,
                            "affect_affectedness": affect.affectedness,
                            "affect_impact": affect.impact,
                            "affect_resolution": affect.resolution,
                        }
                    )
            components.append(
                {
                    "link": f"{CORGI_SERVER_URL}/api/v1/product_versions?name={self.product_version_name}",  # noqa
                    "name": self.product_version_name,
                    "affects": affects,
                }
            )

        return components
