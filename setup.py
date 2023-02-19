"""griffon Python Package

This setup.py file uses setuptools to install the `griffon` package
"""

from setuptools import setup

with open("README.md") as f:
    readme = f.read()

with open("griffon/__init__.py") as f:
    for line in f:
        if line.startswith("__version__"):
            delim = '"' if '"' in line else "'"
            version = line.split(delim)[1]
            break
    else:
        raise RuntimeError("Unable to find version string.")

setup(
    name="griffon",
    version=version,
    long_description=readme,
    long_description_content_type="text/markdown",
    url="https://github.com/RedHatProductSecurity/griffon",
    description="Red Hat Product Security CLI",
    packages=[
        "griffon",
        "griffon/commands",
        "griffon/commands/plugins",
        "griffon/services",
        "griffon/autocomplete",
    ],
    install_requires=[
        "click",
        "click-completion",
        "rich",
        "osidb-bindings",
        "component-registry-bindings",
        "packageurl-python",
    ],
    entry_points={"console_scripts": ["griffon=griffon.cli:cli"]},
    author="James Fuller, Red Hat Product Security",
    license="MIT",
    classifiers=[
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
    ],
)
