import logging
import os

import corgi_bindings
import osidb_bindings
from rich.logging import RichHandler

__version__ = "0.1.0"

CORGI_API_URL = os.environ["CORGI_API_URL"]
OSIDB_API_URL = os.environ["OSIDB_API_URL"]


def get_logging(level="INFO"):
    FORMAT = "%(message)s"
    logging.basicConfig(level=level, format=FORMAT, datefmt="[%X]", handlers=[RichHandler()])
    return logging.getLogger("rich")


class CorgiService:
    name = "component-registry"
    description = "Red Hat component registry"
    has_binding = True

    @staticmethod
    def create_session():
        """init corgi session"""
        return corgi_bindings.new_session(corgi_server_uri=CORGI_API_URL)

    @staticmethod
    def get_component_types():
        """get component type enum"""
        return corgi_bindings.bindings.python_client.models.component_type_enum.ComponentTypeEnum

    @staticmethod
    def get_component_namespaces():
        """get component namespaces enum"""
        return corgi_bindings.bindings.python_client.models.namespace_enum.NamespaceEnum

    @staticmethod
    def get_component_arch():
        """get component arch enum"""
        pass
        # return corgi_bindings.bindings.python_client.models.arch_enum.ArchEnum


class OSIDBService:
    name = "osidb"
    description = "Open Source Incident database"
    has_binding = True

    @staticmethod
    def create_session():
        """init osidb session"""
        return osidb_bindings.new_session(osidb_server_uri=OSIDB_API_URL)
