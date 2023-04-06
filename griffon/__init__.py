import configparser
import logging
import os
from configparser import ConfigParser
from functools import partial, wraps

import component_registry_bindings
import osidb_bindings
from osidb_bindings.bindings.python_client.models import Affect, Flaw, Tracker
from pkg_resources import resource_filename  # type: ignore
from rich.logging import RichHandler

from griffon.output import console

__version__ = "0.1.14"

if "CORGI_API_URL" not in os.environ:
    print("Must set CORGI_API_URL environment variable.")
    exit(1)
CORGI_API_URL = os.environ["CORGI_API_URL"]

if "OSIDB_API_URL" not in os.environ:
    print("Must set OSIDB_API_URL environment variable.")
    exit(1)
OSIDB_API_URL = os.environ["OSIDB_API_URL"]
OSIDB_USERNAME = os.getenv("OSIDB_USERNAME", "")
OSIDB_PASSWORD = os.getenv("OSIDB_PASSWORD", "")
OSIDB_AUTH_METHOD = os.getenv("OSIDB_AUTH_METHOD", "kerberos")

GRIFFON_CONFIG_DIR = os.getenv("GRIFFON_API_URL", "~/.griffon")
GRIFFON_RC_FILE = "~/.griffonrc"
GRIFFON_DEFAULT_LOG_FILE = os.getenv("GRIFFON_DEFAULT_LOG_FILE", "~/.griffon/history.log")

logger = logging.getLogger("griffon")

RELATED_MODELS_MAPPING = {Flaw: {"affects": Affect}, Affect: {"trackers": Tracker}}


def config_logging(level="INFO"):
    message_format = "%(asctime)s %(name)s %(levelname)s %(message)s"
    logging.basicConfig(
        level=level, format=message_format, datefmt="[%X]", handlers=[RichHandler()]
    )
    # file_handler = logging.FileHandler(os.path.expanduser(GRIFFON_DEFAULT_LOG_FILE))
    # file_handler.setFormatter(formatter)
    # logger.addHandler(file_handler)


def get_config():
    """read ~/.griffonrc ini file, if it does not exist then return some default config"""
    if not os.path.exists(os.path.expanduser(GRIFFON_RC_FILE)):
        default_griffonrc = resource_filename(__name__, "static/default_griffonrc")
        config = configparser.ConfigParser(allow_no_value=True)
        config.read(default_griffonrc)
        return config
    config = ConfigParser()
    config.read(os.path.expanduser(GRIFFON_RC_FILE))
    return config


griffon_config = get_config()


def get_config_option(section, option, default_value=None):
    if griffon_config.has_option(section, option):
        return griffon_config.get(section, option)
    if default_value:
        return default_value
    return None


def list_config_sections():
    return griffon_config.sections()


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

    @staticmethod
    def get_fields(model, prefix=""):
        """
        get model fields and fields of its related models with
        respective prefixes using dot notation

        eg. field, related_model.field, related_model_1.related_model2.field
        """

        # get rid of the self attribute
        fields = [f"{prefix}{field}" for field in model.get_fields().keys()]
        for name, related_model in RELATED_MODELS_MAPPING.get(model, {}).items():
            fields.extend(CorgiService.get_fields(related_model, prefix=f"{prefix}{name}."))

        return fields


class OSIDBService:
    name = "osidb"
    description = "Open Source Incident database"
    has_binding = True

    @staticmethod
    def create_session():
        """init osidb session"""
        try:
            credentials = {}
            if OSIDB_AUTH_METHOD == "credentials":
                credentials["username"] = OSIDB_USERNAME
                credentials["password"] = OSIDB_PASSWORD
            return osidb_bindings.new_session(osidb_server_uri=OSIDB_API_URL, **credentials)
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
        # TODO: FlawResolutionEnum changed to Resolution01FEnum in OSIDB schema
        # due to some weird drf-spectacular naming clash resolution, there is
        # a way ho to set this to a immutable name however this would require
        # new OSIDB release, so importing the current path and once OSIDB schema
        # is changed and released we can change it back to normal
        #
        # return osidb_bindings.bindings.python_client.models.FlawResolutionEnum
        return osidb_bindings.bindings.python_client.models.Resolution01FEnum

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
        # TODO: AffectResolutionEnum changed to Resolution3AcEnum in OSIDB schema
        # due to some weird drf-spectacular naming clash resolution, there is
        # a way ho to set this to a immutable name however this would require
        # new OSIDB release, so importing the current path and once OSIDB schema
        # is changed and released we can change it back to normal
        #
        # return osidb_bindings.bindings.python_client.models.AffectResolutionEnum
        return osidb_bindings.bindings.python_client.models.Resolution3AcEnum

    @staticmethod
    def get_affect_impact():
        """get affect impact enum"""
        return osidb_bindings.bindings.python_client.models.ImpactEnum

    @staticmethod
    def get_flaw_meta_type():
        """get flaw meta type enum"""
        return osidb_bindings.bindings.python_client.models.MetaTypeEnum

    @staticmethod
    def get_fields(model, prefix=""):
        """
        get model fields and fields of its related models with
        respective prefixes using dot notation

        eg. field, related_model.field, related_model_1.related_model2.field
        """

        # get rid of the self attribute
        fields = [f"{prefix}{field}" for field in model.get_fields().keys()]
        for name, related_model in RELATED_MODELS_MAPPING.get(model, {}).items():
            fields.extend(OSIDBService.get_fields(related_model, prefix=f"{prefix}{name}."))

        return fields

    @staticmethod
    def get_meta_attr_fields(model, prefix=""):
        """
        get model meta attr keys and keys of its related models meta attr with
        respective prefixes using dot notation

        eg. key, related_model.key, related_model_1.related_model2.key
        """
        model_meta_attr = model.get_fields().get("meta_attr")
        if model_meta_attr is None:
            return []

        # get rid of the self attribute and add additional wildcard
        fields = [f"{prefix}{field}" for field in model_meta_attr.get_fields().keys() | {"*"}]
        for name, related_model in RELATED_MODELS_MAPPING.get(model, {}).items():
            fields.extend(
                OSIDBService.get_meta_attr_fields(related_model, prefix=f"{prefix}{name}.")
            )

        return fields


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
