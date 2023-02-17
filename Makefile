podman=`which podman`
tox=python3=`which python3`
tox=`which tox`
pc=`which pip-compile`
ps=`which pip-sync`
openssl=`which openssl`

build: Containerfile
	$(podman) build --build-arg CORGI_API_URL="${CORGI_API_URL}" \
					--build-arg OSIDB_API_URL="${OSIDB_API_URL}" \
					--build-arg REQUESTS_CA_BUNDLE="${REQUESTS_CA_BUNDLE}" \
					--build-arg PIP_INDEX_URL="${PIP_INDEX_URL}" \
					--build-arg ROOT_CA_URL="${ROOT_CA_URL}" \
					--tag localhost/griffon:dev .
run:
	podman run --privileged -it -v /etc/krb5.conf:/etc/krb5.conf localhost/griffon:dev

test-all:
	$(tox)

test:
	black .
	$(tox)

smoke-tests:
	scripts/smoke-tests.sh > smoke-tests.log

compile-deps:
	$(pc) --generate-hashes --allow-unsafe requirements/base.in
	$(pc) --generate-hashes --allow-unsafe requirements/test.in
	$(pc) --generate-hashes --allow-unsafe requirements/lint.in
	$(pc) --generate-hashes --allow-unsafe requirements/dev.in

install-dev-deps:
	pip3 install -r requirements/dev.txt

sync-dev-deps:
	pip-sync requirements/dev.txt

install:
	pip install .

shell:
	ipython

setup-venv:
	virtualenv --python=/usr/bin/python3.9 venv

docs:
	tox -e manpages

clean:
	rm -Rf dist
	rm -Rf man
	rm -Rf griffon.egg-info
	rm -Rf build

update:
	git fetch --all
	git rebase origin/main
	pip install .
