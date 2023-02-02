# ![](docs/image/griffon.jpg) Ǥriffon

**WARNING- NOT PROD (yet), no releases, if you use this you are running with scissors ...**  

Red Hat Product Security CLI providing:

* Set of core entity operations on flaws, affects, components, products, etc... for 
searching, listing and retrieving entities.
* Set of read only query service operations answering 'canned' product security related queries
* Set of process service operations (mutation) automating away manual 'drudgery'
* Dynamic, extensible set of custom plugin operations for interacting with external services 

The CLI provides a simple 'facade' over coarse grained security related data services allowing 
for easier aggregation and narrowing of information providing a good security 'signal' 
for end users.


```commandline
> griffon

Usage: griffon [OPTIONS] COMMAND [ARGS]...

  Red Hat Product Security CLI

Options:
  --debug
  --help   Show this message and exit.

Commands:
  configure  Configure operations.
  docs       Links to useful docs.
  entities   List and retrieve entities operations.
  manage     Manage operations.
  service    Service operations.
  z_fcc      FCC plugin
  z_go_vuln  vuln.go.dev plugin
  z_osv      OSV plugin

```

[User guide (quickstart)](docs/user_guide.md)

[Tutorial](docs/tutorial.md)

[Developer guide](docs/developer_guide.md)
