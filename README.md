# ![](docs/image/griffon.jpg) Ǥriffon

**WARNING- NOT PROD (yet), no releases, if you use this you are running with scissors ...**  

Red Hat Product Security CLI providing:

* Set of entity operations on flaws, affects, components, products, etc... for 
searching, listing and retrieving entities.
* Set of service operations answering 'canned' product security related queries
and automating away manual 'drudgery'
* Dynamic, extensible set of custom plugin operations for interacting with external services 

The CLI provides a simple 'facade' over coarse grained security related data services allowing 
for easier aggregation and narrowing of information providing a good security 'signal' 
for end users.

```commandline
> griffon

Usage: griffon [OPTIONS] COMMAND [ARGS]...

  Red Hat Product Security CLI

Options:
  --version                   Display Griffon version.
  --debug                     Debug log level.
  --show-inactive             Show inactive Products.
  --show-purl                 Display full purl.
  --show-upstream             Show UPSTREAM components.
  --format [json|text|table]  Result format (default is text).
  -v                          Verbose output, more detailed search results,
                              can be used multiple times (e.g. -vvv).
  --no-progress-bar           Disable progress bar.
  --no-color                  Disable output of color ansi esc sequences.
  --help                      Show this message and exit.

Commands:
  configure  Configure operations.
  docs       Links to useful docs.
  entities   Entity operations.
  manage     Manage operations.
  plugins    3rd party plugins.
  service    Service operations.


```

To install:

```commandline
pip install griffon
```

To learn more:

[User guide (quickstart)](docs/user_guide.md)

[Tutorial](docs/tutorial.md)

[Developer guide](docs/developer_guide.md)
