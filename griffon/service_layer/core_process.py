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

    def __init__(self) -> None:
        self.corgi_session = CorgiService.create_session()
        self.osidb_session = OSIDBService.create_session()

    def update(self, payload: dict) -> None:
        # create = self.osidb_session.affects.create(payload)
        pass

    def payload(self, ctx) -> dict:
        return {
            "test": "test",
        }

    def execute(self, ctx) -> None:
        return self.update(self.payload(ctx))
