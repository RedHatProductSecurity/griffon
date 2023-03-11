import logging

import requests

from griffon import CORGI_API_URL, OSIDB_API_URL

logger = logging.getLogger("griffon")


def get_product_version_ofuris(ctx, param, incomplete):
    payload = {"limit": 100, "include_fields": "ofuri", "re_ofuri": incomplete}
    response = requests.get(
        f"{CORGI_API_URL}/api/v1/product_versions",
        params=payload,
        headers={"Accept-Encoding": "gzip;q=1.0, identity; q=0.5, *;q=0"},
    )
    ofuris = response.json()["results"]
    return [k["ofuri"] for k in ofuris if k["ofuri"].startswith(incomplete)]


def get_product_version_names(ctx, param, incomplete):
    payload = {"limit": 100, "include_fields": "name", "re_name": incomplete}
    response = requests.get(
        f"{CORGI_API_URL}/api/v1/product_versions",
        params=payload,
        headers={"Accept-Encoding": "gzip;q=1.0, identity; q=0.5, *;q=0"},
    )
    names = response.json()["results"]
    return [k["name"] for k in names if k["name"].startswith(incomplete)]


def get_product_stream_ofuris(ctx, param, incomplete):
    payload = {"limit": 100, "include_fields": "ofuri", "re_ofuri": incomplete}
    response = requests.get(
        f"{CORGI_API_URL}/api/v1/product_streams",
        params=payload,
        headers={"Accept-Encoding": "gzip;q=1.0, identity; q=0.5, *;q=0"},
    )
    ofuris = response.json()["results"]
    return [k["ofuri"] for k in ofuris if k["ofuri"].startswith(incomplete)]


def get_product_stream_names(ctx, param, incomplete):
    payload = {"limit": 100, "include_fields": "name", "re_name": incomplete}
    response = requests.get(
        f"{CORGI_API_URL}/api/v1/product_streams",
        params=payload,
        headers={"Accept-Encoding": "gzip;q=1.0, identity; q=0.5, *;q=0"},
    )
    names = response.json()["results"]
    return [k["name"] for k in names if k["name"].startswith(incomplete)]


def get_component_names(ctx, param, incomplete):
    payload = {"limit": 100, "include_fields": "name", "re_name": incomplete}
    response = requests.get(
        f"{CORGI_API_URL}/api/v1/components",
        params=payload,
        headers={"Accept-Encoding": "gzip;q=1.0, identity; q=0.5, *;q=0"},
    )
    names = response.json()["results"]
    return list(set([k["name"] for k in names if k["name"].startswith(incomplete)]))


def get_component_purls(ctx, param, incomplete):
    payload = {"limit": 100, "include_fields": "purl", "re_purl": incomplete}
    response = requests.get(
        f"{CORGI_API_URL}/api/v1/components",
        params=payload,
        headers={"Accept-Encoding": "gzip;q=1.0, identity; q=0.5, *;q=0"},
    )
    names = response.json()["results"]
    return list(set([k["purl"] for k in names if k["purl"].startswith(incomplete)]))


def get_cve_ids(ctx, param, incomplete):
    """TODO - the following is not ideal for autocomplete lookup - need to investigate"""
    response = requests.get(
        f"{OSIDB_API_URL}/osidb/api/v1/flaws?limit=10&re_cve_id={incomplete}&include_fields=cve_id"  # noqa
    )
    return [k["cve_id"] for k in response.json()["results"] if k["cve_id"].startswith(incomplete)]
