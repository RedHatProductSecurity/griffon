"""
    griffon cli

"""
import configparser
import logging
import os
from configparser import ConfigParser
from contextlib import contextmanager
from functools import partial, wraps

import component_registry_bindings
import osidb_bindings
from osidb_bindings.bindings.python_client.models import Affect, Flaw, Tracker
from pkg_resources import resource_filename
from rich.logging import RichHandler

from griffon.helpers import Color, Style
from griffon.output import console

__version__ = "0.4.1"

# TODO: Deprecate CORGI_API_URL completely in the next version or two
CORGI_SERVER_URL = os.getenv("CORGI_SERVER_URL", os.getenv("CORGI_API_URL"))
# TODO: Deprecate OSIDB_API_URL completely in the next version or two
OSIDB_SERVER_URL = os.getenv("OSIDB_SERVER_URL", os.getenv("OSIDB_API_URL"))

OSIDB_USERNAME = os.getenv("OSIDB_USERNAME", "")
OSIDB_PASSWORD = os.getenv("OSIDB_PASSWORD", "")
OSIDB_AUTH_METHOD = os.getenv("OSIDB_AUTH_METHOD", "kerberos")

# TODO: Deprecate COMMUNITY_COMPONENTS_API_URL completely in the next version or two
# required to enable --search-community
COMMUNITY_COMPONENTS_SERVER_URL = os.getenv(
    "COMMUNITY_COMPONENTS_SERVER_URL",
    os.getenv("COMMUNITY_COMPONENTS_API_URL", "https://component-registry.fedoraproject.org"),
)

# TODO: temporary hack required to enable searching of middleware
MIDDLEWARE_CLI = os.getenv("GRIFFON_MIDDLEWARE_CLI")

GRIFFON_CONFIG_DIR = os.getenv("GRIFFON_API_URL", "~/.griffon")
GRIFFON_RC_FILE = "~/.griffonrc"
GRIFFON_DEFAULT_LOG_FILE = os.getenv("GRIFFON_DEFAULT_LOG_FILE", "~/.griffon/history.log")

logger = logging.getLogger("griffon")

RELATED_MODELS_MAPPING = {Flaw: {"affects": Affect}, Affect: {"trackers": Tracker}}


def check_envvars():
    """Check that all necessary envvars are set"""

    # TODO: Deprecate CORGI_API_URL completely in the next version or two
    if "CORGI_API_URL" in os.environ:
        print(
            (
                f"{Style.BOLD}{Color.YELLOW}WARNING: CORGI_API_URL will be deprecated "
                "in the next version of Griffon in favour of CORGI_SERVER_URL, please "
                f"switch to the new environment variable.{Style.RESET}"
            )
        )
    if "CORGI_SERVER_URL" not in os.environ and "CORGI_API_URL" not in os.environ:
        print("Must set CORGI_SERVER_URL environment variable.")
        exit(1)

    # TODO: Deprecate COMMUNITY_COMPONENTS_API_URL completely in the next version or two
    if "COMMUNITY_COMPONENTS_API_URL" in os.environ:
        print(
            (
                f"{Style.BOLD}{Color.YELLOW}WARNING: COMMUNITY_COMPONENTS_API_URL "
                "will be deprecated in the next version of Griffon in favour of "
                "COMMUNITY_COMPONENTS_SERVER_URL, please switch to the new environment "
                f"variable.{Style.RESET}"
            )
        )

    # TODO: Deprecate OSIDB_API_URL completely in the next version or two
    if "OSIDB_API_URL" in os.environ:
        print(
            (
                f"{Style.BOLD}{Color.YELLOW}WARNING: OSIDB_API_URL will be deprecated "
                "in the next version of Griffon in favour of OSIDB_SERVER_URL, please "
                f"switch to the new environment variable.{Style.RESET}"
            )
        )
    if "OSIDB_SERVER_URL" not in os.environ and "OSIDB_API_URL" not in os.environ:
        print("Must set OSIDB_SERVER_URL environment variable.")
        exit(1)


def config_logging(level="INFO"):
    # if set to 'DEBUG' then we want all the http conversation
    if level == "DEBUG":
        import http.client as http_client

        http_client.HTTPConnection.debuglevel = 1

    message_format = "%(asctime)s %(name)s %(levelname)s %(message)s"
    logging.basicConfig(
        level=level, format=message_format, datefmt="[%X]", handlers=[RichHandler()]
    )


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
    return default_value


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
                component_registry_server_uri=CORGI_SERVER_URL,
            )
        except:  # noqa
            console.log(f"{CORGI_SERVER_URL} is not accessible.")
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
            return osidb_bindings.new_session(osidb_server_uri=OSIDB_SERVER_URL, **credentials)
        except:  # noqa
            console.log(f"{OSIDB_SERVER_URL} is not accessible (or krb ticket has expired).")
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
        return osidb_bindings.bindings.python_client.models.ResolutionEnum

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
        return osidb_bindings.bindings.python_client.models.ResolutionEnum

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


class CommunityComponentService:
    name = "community-component-registry"
    description = "Red Hat component registry"
    has_binding = True

    @staticmethod
    def create_session():
        """init corgi session"""
        try:
            return component_registry_bindings.new_session(
                component_registry_server_uri=COMMUNITY_COMPONENTS_SERVER_URL,
            )
        except:  # noqa
            console.log(f"{COMMUNITY_COMPONENTS_SERVER_URL } is not accessible.")
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


@contextmanager
def console_status(no_progress_bar, initial_status=None):
    """updatable console status progress bar"""

    class DisabledStatusObject:
        """
        Dummy disabled status object for graceful handle of
        no progress bar option
        """

        def __getattr__(self, attr):
            def dummy_method(*args, **kwargs):
                pass  # Do nothing when any method is called

            return dummy_method

    class StatusObject:
        """
        Status object for default Griffon status handling
        """

        def __init__(self, status):
            self.status = status

        def update(self, status, *args, **kwargs):
            self.status.update(
                status=f"[magenta b]griffoning:[/magenta b] [bold]{status}[/bold]", *args, **kwargs
            )

        def start(self):
            self.status.start()

        def stop(self):
            self.status.stop()

    if no_progress_bar:
        yield DisabledStatusObject()
    else:
        status = f": {initial_status}" if initial_status else ""

        with console.status(
            f"[magenta b]griffoning[/magenta b]{status}", spinner="line"
        ) as operation_status:
            yield StatusObject(operation_status)


def progress_bar(is_updatable=False, initial_status=None):
    """
    progress bar decorator

    :param updatable: allows/disallows updatable progress bar status, if set to `True`
    decorated function needs to have `operation_status` parameter
    """

    def decorator(func=None):
        if not func:
            return partial(decorator)

        @wraps(func)
        def wrapper(*args, **kwargs):
            obj: dict = args[0].obj
            with console_status(obj.get("NO_PROGRESS_BAR"), initial_status) as operation_status:
                if is_updatable:
                    func(*args, operation_status=operation_status, **kwargs)
                else:
                    func(*args, **kwargs)

        return wrapper

    return decorator


def progress_bar2(
    func=None,
):
    """progress bar decorator"""
    if not func:
        return partial(progress_bar)

    @wraps(func)
    def wrapper(*args, **kwargs):
        obj: dict = args[0].obj
        with console_status(obj.get("NO_PROGRESS_BAR")) as operation_status:
            func(*args, operation_status=operation_status, **kwargs)

    return wrapper


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    print(f"Version {__version__}")
    ctx.exit()
