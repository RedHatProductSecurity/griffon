"""

"""

import click

from griffon import CORGI_API_URL, OSIDB_API_URL


@click.group(name="docs", help="Links to useful docs.")
@click.pass_context
def docs_grp(ctx):
    pass


@docs_grp.command()
def griffon_github():
    click.launch("https://github.com/RedHatProductSecurity/griffon")


@docs_grp.command()
def griffon_tutorial():
    click.launch("https://github.com/RedHatProductSecurity/griffon/blob/main/docs/tutorial.md")


@docs_grp.command()
def osidb():
    click.launch(OSIDB_API_URL)


@docs_grp.command()
def osidb_github():
    click.launch("https://github.com/RedHatProductSecurity/osidb")


@docs_grp.command()
def osidb_tutorial():
    click.launch("https://github.com/RedHatProductSecurity/osidb/blob/master/docs/user/TUTORIAL.md")


@docs_grp.command()
def osidb_bindings():
    click.launch("https://github.com/RedHatProductSecurity/osidb-bindings/blob/master/TUTORIAL.md")


@docs_grp.command()
def corgi():
    click.launch(CORGI_API_URL)


@docs_grp.command()
def corgi_github():
    click.launch("https://github.com/RedHatProductSecurity/component-registry")


@docs_grp.command()
def corgi_tutorial():
    click.launch(
        "https://github.com/RedHatProductSecurity/component-registry/blob/main/docs/user_guide.md"
    )
