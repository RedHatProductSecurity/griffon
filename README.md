# ![](docs/image/griffon.png) Ǥriffon

Red Hat Product Security CLI providing:

* Set of service operations answering 'canned' product security related queries
and automating away some manual 'drudgery'
* Dynamic, extensible set of custom plugin operations for interacting with external services 
* Set of entity operations on flaws, affects, components, products, etc... for 
searching, listing and retrieving entities.

The CLI provides a 'facade' over coarse grained security related data services allowing 
for easier aggregation and narrowing of security information.

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

[User guide (quickstart)](https://github.com/RedHatProductSecurity/griffon/tree/main/docs/user_guide.md)

[Tutorial](https://github.com/RedHatProductSecurity/griffon/tree/main/docs/tutorial.md)

[Developer guide](https://github.com/RedHatProductSecurity/griffon/tree/main/docs/developer_guide.md)
