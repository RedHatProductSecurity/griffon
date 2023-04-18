# User documentation

## Usage

Learn how to use griffon cli by using its built in autocompletion 
and help information provided at the command line.

For more information, please read the [tutorial](tutorial.md). 

## Installation

### Install software

You will need the following dependencies installed, for example for fedora 35:

* python39
* gcc (to build gssapi wheel)
* python-39-devel (to build gssapi wheel)
* krb5-workstation (provides access to OSIDB) with valid /etc/krb5.config
* virtualenv (if you do not want to install python deps into your system)

or more generally

* python
* gcc (to build gssapi wheel)
* python-devel (to build gssapi wheel)
* krb5-workstation (provides access to OSIDB) with valid /etc/krb5.config
* virtualenv (if you do not want to install python deps into your system)

Setup virtualenv
```commandline
> python3.9 -m venv venv
> source venv/bin/activate
```

The installation process should just be:
```commandline
pip install griffon
```
and check version that was installed with
```commandline
griffon --version
```
To force installation
```commandline
pip install --force griffon
```
To uninstall
```commandline
pip uninstall griffon
```

### Set env vars

Set the following env vars

Ensure REQUESTS_CA_BUNDLE is set and accessible in your environment
```commandline
export REQUESTS_CA_BUNDLE=/etc/pki/tls/certs/ca-bundle.crt
```

Set service urls.
```commandline
export OSIDB_API_URL="https://<INSERT OSIDB API URL>"
export CORGI_API_URL="https://<INSERT COMPONENT REGISTRY API URL>"
```

and the following is set to enable searching community components:
```commandline
export COMMUNITY_COMPONENTS_API_URL="https://component-registry.fedoraproject.org"
```

Your system must be properly authorised to access all these systems.

**hint**- run kinit to be able to access OSIDB.

If you want to make changes to the OSIDB entities you need to supply your Bugzilla API key as well:
```commandline
export BUGZILLA_API_KEY="<your Bugzilla API key>"
```

If you want to use local development instance of OSIDB you need to specify authentication method
and supply credentials to your local OSIDB environment:
```commandline
export OSIDB_AUTH_METHOD="credentials"
export OSIDB_USERNAME="<your username>"
export OSIDB_PASSWORD="<your password>"
```

### Enable autocompletion
Enable shell autocompletion by following these instructions for your specific shell.

Ensuring to source (ex. source ~/.zshrc) to pickup the change. 

https://click.palletsprojects.com/en/8.1.x/shell-completion/

#### bash
Add this to ~/.bashrc:
```commandline
eval "$(_GRIFFON_COMPLETE=bash_source griffon)"
```

#### zsh
Add this to ~/.zshrc:
```commandline
eval "$(_GRIFFON_COMPLETE=zsh_source griffon)"
```


## Building and running container
The container is unsupported.

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

Griffon can be extended with custom plugins - handy for integrating with 3rd party services.

To create plugins emulate provided [examples](https://github.com/RedHatProductSecurity/griffon/tree/main/griffon/commands/plugins)

The **griffon/commands/plugins** directory (in your python site packages) will dynamically
register custom plugins.

The **~/.griffonrc** defines a directory (default ~/.griffon/plugins) where you can drop in your own custom plugins.

If you think your custom plugin could be useful for others then raise a [pull request](https://github.com/RedHatProductSecurity/griffon/pulls).

