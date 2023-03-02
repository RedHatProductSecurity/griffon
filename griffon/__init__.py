import configparser
import logging
import os
from configparser import ConfigParser
from functools import partial, wraps

import component_registry_bindings
import osidb_bindings
from rich.logging import RichHandler

from griffon.output import console

__version__ = "0.0.7"

CORGI_API_URL = os.environ["CORGI_API_URL"]
OSIDB_API_URL = os.environ["OSIDB_API_URL"]

GRIFFON_CONFIG_DIR = os.getenv("GRIFFON_API_URL", "~/.griffon")
GRIFFON_RC_FILE = "~/.griffonrc"
GRIFFON_DEFAULT_LOG_FILE = "~/.griffon/griffon.log"

logging.basicConfig(level="INFO")
logger = logging.getLogger("griffon")

# file_handler = logging.FileHandler(os.path.expanduser(GRIFFON_DEFAULT_LOG_FILE))
formatter = logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")
# file_handler.setFormatter(formatter)
# logger.addHandler(file_handler)
logger.handlers = [RichHandler()]

logger = logging.getLogger("griffon")


def get_config():
    """read ~/.griffonrc ini file, if it does not exist then return some default config"""
    if not os.path.exists(os.path.expanduser(GRIFFON_RC_FILE)):
        config = configparser.ConfigParser(allow_no_value=True)
        config.optionxform = str
        config.add_section("default")
        config["default"]["log_file"] = GRIFFON_DEFAULT_LOG_FILE
        config["default"]["format"] = "text"
        config.add_section("exclude")
        return config
    config = ConfigParser()
    config.read(os.path.expanduser(GRIFFON_RC_FILE))
    return config


class CorgiService:
    name = "component-registry"
    description = "Red Hat component registry"
    has_binding = True

    @staticmethod
    def create_session():
        """init corgi session"""
        try:
            return component_registry_bindings.new_session(
                component_registry_server_uri=CORGI_API_URL
            )
        except:  # noqa
            console.log(f"{CORGI_API_URL} is not accessible.")
            exit(1)

    @staticmethod
    def get_component_types():
        """get component type enum"""
        return (
            component_registry_bindings.bindings.python_client.models.component_type_enum.ComponentTypeEnum  # noqa
        )

    @staticmethod
    def get_component_namespaces():
        """get component namespaces enum"""
        return (
            component_registry_bindings.bindings.python_client.models.namespace_enum.NamespaceEnum
        )

    @staticmethod
    def get_component_arches():
        """get component arch enum"""
        return [
            "src",
            "noarch",
            "i386",
            "ia64",
            "s390",
            "x86_64",
            "s390x",
            "ppc",
            "ppc64",
            "aarch64",
            "ppc64le",
        ]


class OSIDBService:
    name = "osidb"
    description = "Open Source Incident database"
    has_binding = True

    @staticmethod
    def create_session():
        """init osidb session"""
        try:
            return osidb_bindings.new_session(osidb_server_uri=OSIDB_API_URL)
        except:  # noqa
            console.log(f"{OSIDB_API_URL} is not accessible (or krb ticket has expired).")
            exit(1)

    @staticmethod
    def get_flaw_states():
        """get flaw states enum"""
        return osidb_bindings.bindings.python_client.models.FlawClassificationState

    @staticmethod
    def get_flaw_resolutions():
        """get flaw resolution enum"""
        return osidb_bindings.bindings.python_client.models.FlawResolutionEnum

    @staticmethod
    def get_flaw_impacts():
        """get flaw impacts enum"""
        return osidb_bindings.bindings.python_client.models.ImpactEnum

    @staticmethod
    def get_affect_affectedness():
        """get affect affectedness enum"""
        return osidb_bindings.bindings.python_client.models.AffectednessEnum

    @staticmethod
    def get_affect_resolution():
        """get affect affectedness enum"""
        return osidb_bindings.bindings.python_client.models.AffectResolutionEnum

    @staticmethod
    def get_affect_impact():
        """get affect impact enum"""
        return osidb_bindings.bindings.python_client.models.ImpactEnum


def progress_bar(
    func=None,
):
    """progress bar decorator"""
    if not func:
        return partial(progress_bar)

    @wraps(func)
    def wrapper(*args, **kwargs):
        obj: dict = args[0].obj
        if obj.get("NO_PROGRESS_BAR"):
            func(*args, **kwargs)
        else:
            with console.status("griffoning", spinner="line"):
                func(*args, **kwargs)

    return wrapper


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    print(f"Version {__version__}")
    ctx.exit()
