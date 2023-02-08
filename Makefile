python3=`which python3`
tox=`which tox`
pc=`which pip-compile`
ps=`which pip-sync`
openssl=`which openssl`

test-all:
	$(tox)

test:
	black .
	$(tox) -e isort
	$(tox) -e flake8
	$(tox) -e griffon

compile-deps:
	$(pc) --generate-hashes --allow-unsafe requirements/base.in
	$(pc) --generate-hashes --allow-unsafe requirements/test.in
	$(pc) --generate-hashes --allow-unsafe requirements/lint.in
	$(pc) --generate-hashes --allow-unsafe requirements/dev.in

install:
	pip install .

install-dev-deps:
	pip3 install -r requirements/dev.txt

sync-dev-deps:
	pip-sync requirements/dev.txt

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
