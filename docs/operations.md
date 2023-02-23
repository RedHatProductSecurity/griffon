# Griffon -- operations

## CI

github actions

define secrets 

## Release

Follow this procedure when performing Griffon version X.Y.Z release.


1) Checkout main branch

    ```
    $ git checkout main
    $ git fetch --all
    $ git rebase origin/main
    ```

2) Create release branch

    * create a new release branch
    * increment the patch part of the version in all necessary places (eg. x.x.1 -> x.x.2)
    * ensure CHANGELOG.md is updated accordingly
    * commit / push changes to release branch
    * raise PR

3) Review and merge PR

4) Create a new release and tag via [GitHub WebUI](https://github.com/RedHatProductSecurity/griffon/releases/new) - this will also trigger the build and upload to PyPI
    * Tag and release needs be in format x.x.x to comply with [semantic versioning](#version-policy)
    * Tag needs to point to the latest commit
    * Release description should include the newest section of the [CHANGELOG.md](CHANGELOG.md)

## Versioning

Griffon uses [Semantic Versioning](https://semver.org/). 

We start versioning with v0.1.0.

Additionally, we consider Griffon 1.0.0 as the first General Availability version.
