# Griffon -- operations

## CI

github actions

define secrets

## Release

Follow this procedure when performing Griffon version X.Y.Z release.

1) Clone/update master branch

    ```
    $ git checkout main
    $ git fetch --all
    $ git rebase origin/main
    ```

2) Start release script and follow instructions

    ```
    $ make release type=<major|minor|patch>
    ```
    NOTE: if `type` is not specified, patch release will be performed

    This will:
    * create a new branch
    * replace version on all places with new Griffon version based on the latest Griffon version and release type
    * commit and push the changes
    * open pull request creation in browser

3) Confirm PR creation opened by the relase script

4) Confirm checks passes

5) Merge PR

6) Create a new release and tag via [GitHub WebUI](https://github.com/RedHatProductSecurity/griffon/releases/new) - this will also trigger the build and upload to PyPI
    * Tag and release needs be in format x.x.x to comply with [semantic versioning](#version-policy)
    * Tag needs to point to the latest commit
    * Release description should include the newest section of the [CHANGELOG.md](CHANGELOG.md)

## Versioning

Griffon uses [Semantic Versioning](https://semver.org/).

Griffon starts official versioning at v0.1.0.
