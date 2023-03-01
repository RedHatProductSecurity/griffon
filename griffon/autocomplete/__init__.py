import logging

import requests

from griffon import CORGI_API_URL, OSIDB_API_URL

logger = logging.getLogger("griffon")


def get_product_version_ofuris(ctx, param, incomplete):
    response = requests.get(
        f"{CORGI_API_URL}/api/v1/product_versions?limit=1000&include_fields=ofuri&re_ofuri={incomplete}"  # noqa
    )
    return [k["ofuri"] for k in response.json()["results"] if incomplete in k["ofuri"]]


def get_product_version_names(ctx, param, incomplete):
    response = requests.get(
        f"{CORGI_API_URL}/api/v1/product_versions?limit=1000&include_fields=name&re_name={incomplete}"  # noqa
    )
    return [k["name"] for k in response.json()["results"] if incomplete in k["name"]]


def get_product_stream_ofuris(ctx, param, incomplete):
    payload = {"limit": 2000, "include_fields": "ofuri", "re_ofuri": incomplete}
    # if ctx.obj["SHOW_INACTIVE"]:
    #     payload["active"] = "all"
    response = requests.get(
        f"{CORGI_API_URL}/api/v1/product_streams",
        params=payload,
    )
    return [k["ofuri"] for k in response.json()["results"] if incomplete in k["ofuri"]]


def get_product_stream_names(ctx, param, incomplete):
    payload = {"limit": 2000, "include_fields": "name", "re_name": incomplete}
    # if ctx.obj["SHOW_INACTIVE"]:
    #     payload["active"] = "all"
    response = requests.get(
        f"{CORGI_API_URL}/api/v1/product_streams",
        params=payload,
    )
    names = response.json()["results"]
    return [k["name"] for k in names if "name" in k]


def get_component_names(ctx, param, incomplete):
    response = requests.get(
        f"{CORGI_API_URL}/api/v1/components?include_fields=name&re_name={incomplete}&limit=100"  # noqa
    )
    names = response.json()["results"]
    return list(set([k["name"] for k in names if "name" in k]))


def get_component_purls(ctx, param, incomplete):
    response = requests.get(
        f"{CORGI_API_URL}/api/v1/components?include_fields=purl&re_purl={incomplete}&limit=20"  # noqa
    )
    return [k["purl"] for k in response.json()["results"]]


def get_cve_ids(ctx, param, incomplete):
    """TODO - the following is not ideal for autocomplete lookup - need to investigate"""
    response = requests.get(
        f"{OSIDB_API_URL}/osidb/api/v1/flaws?limit=10&re_cve_id={incomplete}&include_fields=cve_id"  # noqa
    )
    return [k["cve_id"] for k in response.json()["results"] if incomplete in k["cve_id"]]
