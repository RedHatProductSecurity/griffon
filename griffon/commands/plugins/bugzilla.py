"""
bugzilla plugin:

> griffon plugins bugzilla setup


"""
import logging
import os
import subprocess

import click

logger = logging.getLogger("griffon")

bz_token = os.getenv("BZIMPORT_BZ_API_KEY")
bz_url = os.getenv("BZIMPORT_BZ_URL", "https://bugzilla.redhat.com")

activeprods = [
    "Red Hat Enterprise Linux 5",
    "Red Hat Enterprise Linux 6",
    "Red Hat Enterprise Linux 7",
    "Red Hat Enterprise Linux 8",
    "Red Hat Enterprise Linux 9",
    "Red Hat Software Collections",
    "Fedora",
    "Fedora EPEL",
    "JBoss Enterprise Application Platform 5",
    "JBoss Enterprise Application Platform 6",
    "JBoss Enterprise Web Server 2",
    "Red Hat Developer Toolset",
    "Red Hat Certificate System",
    "Red Hat Enterprise MRG",
    "Red Hat OpenStack",
    "Red Hat Satellite",
    "Subscription Asset Manager",
    "Red Hat Gluster Storage",
]


@click.group(help="bugzilla plugin ")
@click.pass_context
def plugins(ctx):
    """bugzilla plugin"""
    pass


try:
    # ensure python-bugzilla is installed
    from bugzilla import Bugzilla

    @plugins.command(help="bzowner")
    @click.argument("component", required=True)
    @click.option(
        "--json",
        "json_format",
        is_flag=True,
        default=False,
        help="json format.",
    )
    @click.pass_context
    def get_bugzilla_owners(ctx, component, json_format):
        """
        inspired by previous work
        """

        bz_api = Bugzilla(bz_url, api_key=bz_token)
        query = {
            "names": [{"product": p, "component": component} for p in activeprods],
            "include_fields": ["name", "product_name", "default_assignee", "default_cc"],
        }
        result = bz_api._proxy.Component.get(query)

        if json_format:
            click.echo(result)
        else:
            for c in result["components"]:
                tmp = c["product_name"] + " - " + c["default_assignee"]
                if len(c["default_cc"]) > 0:
                    tmp += " [cc: " + " ".join(c["default_cc"]) + "]"
                click.echo(tmp)

except Exception:
    pass


@plugins.command(help="Run this first to ensure python-bugzilla module dependency is installed")
@click.pass_context
def setup(ctx):
    subprocess.run(["pip", "install", "python-bugzilla"])
