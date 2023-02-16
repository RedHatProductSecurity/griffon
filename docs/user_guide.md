# User documentation

## Usage

Learn how to use griffon cli by using its built in autocompletion 
and help information provided at the command line.

Otherwise, please read the (under development) [tutorial](tutorial.md). 

## Installation

### Install software

***WARNING-COMPONENT-REGISTRY bindings are not yet deployed on PyPI - will have to install manually from gitlab repo.***

You will need the following dependencies installed

* python39
* python-39-devel (so gssapi wheel can be built)
* krb5-workstation (provides access to OSIDB)
* virtualenv (if you do not want to install python deps into your system)

Clone git repo
```commandline
> git clone https://github.com/RedHatProductSecurity/griffon.git
> cd griffon
```
Setup virtualenv (if you do not want griffon installed in your system)
```commandline
> python3.9 -m venv venv
> source venv/bin/activate
```
Install python requirements and the griffon app
```commandline
> pip install -r requirements/base.txt
> pip install .
```
As we are under heavy development ... to pick up latest changes (after initial
installation)
```commandline
> git fetch --all
> git rebase origin/main
> pip install .
```

**Note**- Eventually we will distribute via PyPI (**NOT SUPPORTED YET**) where 
the installation process should just be:
```commandline
pip install griffon
```

### Set env vars

Set the following env vars

Ensure REQUESTS_CA_BUNDLE is set and accessible in your environment
```commandline
export REQUESTS_CA_BUNDLE=/etc/pki/tls/certs/ca-bundle.crt
```
and set service urls.
```commandline
export OSIDB_API_URL=https://<INSERT OSIDB API URL>
export CORGI_API_URL=https://<INSERT COMPONENT REGISTRY API URL>
```
And you must ensure your system is properly authorised to access these systems.

**hint**- usually that means run > kinit

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


## Building and running container

First set some env vars

```commandline
export CORGI_API_URL=<INSERT COMPONENT REGISTRY URL>
export OSIDB_API_URL=<INESRT OSIDB URL>
export REQUESTS_CA_BUNDLE=<INSERT CA BUNDLE PATH>
export PIP_INDEX_URL=<INSERT PIP INDEX URL>
export ROOT_CA_URL=<INSERT ROOT CA URL >
```
then run make target for building container

```commandline
> make build
```

Once the container is successfully built 

```commandline
> podman run --privileged -it -v /etc/krb5.conf:/etc/krb5.conf localhost/griffon:latest
```
then you will have to kinit with your user name (inside the container) before you use 
griffon.

**Note** - This is a temporary container for current development ... at some point
we will make a release container.

## Writing custom plugins

Griffon can be extended with custom plugins - handy for integrating with 
3rd party services.

To create plugins emulate provided [examples](https://github.com/RedHatProductSecurity/griffon/tree/main/griffon/commands/plugins)

The **griffon/commands/plugins** directory (in your python site packages) will dynamically
register custom plugins.

If you think your custom plugin could be useful for others then
raise a [pull request](https://github.com/RedHatProductSecurity/griffon/pulls).

## Writing custom service processes or queries

The griffon/service_layer directory contains service query and operations.
