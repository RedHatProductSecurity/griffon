import logging

from griffon.autocomplete import product_streams, product_versions

logger = logging.getLogger("rich")


def get_product_version_ofuris(ctx, param, incomplete):
    return [k for k in product_versions.ofuris if k.startswith(incomplete)]


def get_product_version_names(ctx, param, incomplete):
    return [k for k in product_versions.product_version_names if k.startswith(incomplete)]


def get_product_stream_ofuris(ctx, param, incomplete):
    return [k for k in product_streams.ofuris if k.startswith(incomplete)]


def get_product_stream_names(ctx, param, incomplete):
    return [k for k in product_streams.product_stream_names if k.startswith(incomplete)]


def get_cve_ids(ctx, param, incomplete):
    """TODO - the following is not ideal for autocomplete lookup - need to investigate"""
    # response = requests.get(
    #     f"{OSIDB_API_URL}/osidb/api/v1/flaws?limit=5&search={incomplete}&include_fields=cve_id,title"  # noqa
    # )
    # return [k["cve_id"] for k in response.json()["results"]]
    pass
