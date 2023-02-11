"""
    mutation

    inputs and mutation output
"""

from griffon import CorgiService, OSIDBService


# TODO - stub
class generate_affects_for_specific_component_process:
    """Generate OSIDB affects for a specific component."""

    name = "generate_affects_for_specific_component"
    description = "Generate osidb affects for a specific component."

    def __init__(self, params: dict) -> None:
        self.corgi_session = CorgiService.create_session()
        self.osidb_session = OSIDBService.create_session()
        self.params = params

    def update(self) -> None:
        pass
