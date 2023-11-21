#!/usr/bin/env bash
# perform a release

source scripts/helpers.sh

# Get number of the new Griffon version
# $1: release type (major|minor|patch)
get_new_version() {
    local release_type=${1}

    # Parse current version from griffon __init__.py
    current_version=$(cat griffon/__init__.py | grep -Po '(?<=__version__ = \")\d+\.\d+\.\d+')
    new_version=$(increment_version ${current_version} ${release_type})
}

# Main section
check_are_you_serious ${1}
check_main_branch
get_new_version ${1}

create_new_branch "v${new_version}"
update_version ${new_version}
review
commit_version_changes ${new_version}

push_branch "v${new_version}"
pull_request ${new_version}

exit 0
