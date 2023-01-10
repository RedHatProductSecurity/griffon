# User documentation

## Installation

### Install software

***WARNING-COMPONENT-REGISTRY bindings are not yet deployed on PyPI - will have to install manually from gitlab repo.***

You will need the following dependencies installed

* python39
* python-39-devel (so gssapi wheel can be built)
* krb5-workstation (provides access to OSIDB)
* virtualenv (if you do not want to install python deps into your system)

Download repo, install requirements and install griffon with pip

```commandline
git clone https://github.com/RedHatProductSecurity/griffon.git
cd griffon
pip install -r requirements/base.txt
pip install .
```
or directly install it from github repo:
```commandline
pip install -e git+https://github.com/RedHatProductSecurity/griffon.git#egg=griffon
```
or download zip of repo and expand.

Eventually we will distribute via PyPI (**NOT SUPPORTED YET**)
```commandline
pip install griffon
```

### Set env vars

Set the following env vars
```commandline
export OSIDB_API_URL=https://<INSERT OSIDB API URL>
export CORGI_API_URL=https://<INSERT COMPONENT REGISTRY API URL>
```
And ensure your system is properly authorised to access these systems.

**hint**- typically that means run > kinit

### Enable autocompletion
Enable shell autocompletion by following these instructions for your specific shell.

Add this to ~/.bashrc:

```commandline
eval "$(_GRIFFON_COMPLETE=bash_source griffon)"
```

Add this to ~/.zshrc:

```commandline
eval "$(_GRIFFON_COMPLETE=zsh_source griffon)"
```

ensuring to source (ex. source ~/.zshrc) to pickup the change. 

https://click.palletsprojects.com/en/8.1.x/shell-completion/

## Usage

......




Some more examples

```commandline
griffon entities components list --re_name ansible --version 1.1.1
griffon entities components get --purl "pkg:rpm/redhat/curl@7.29.0-19.el7?arch=aarch64" 
griffon entities product-streams get_latest_components --ofuri o:redhat:rhel:9.1.0.z
griffon queries component_cves --purl "pkg:rpm/redhat/systemd@239-45.el8_4.11?arch=aarch64" --affectedness AFFECTED
griffon entities components list --name curl | jq '.results[].purl'

griffon queries products_containing_specific_component --purl "pkg:rpm/redhat/systemd@239-45.el8_4.11?arch=aarch64" | jq ".product_streams"

```


## Writing custom plugins

Griffon can be extended with custom plugins - handy for integrating with 
3rd party services.

To create plugins emulate provided [examples](griffon/commands/plugins)

The **griffon/commands/plugins** directory (in your python site packages) will dynamically
register custom plugins.

If you think your custom plugin could be useful for others then
raise a [pull request](https://github.com/RedHatProductSecurity/griffon/pulls).

## Writing custom service processes or queries

The griffon/service_layer directory contains service query and operations.
