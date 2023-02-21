"""

"""

import os

import click

plugin_folder = os.path.join(os.path.dirname(__file__), "plugins")


class plugin_commands(click.MultiCommand):
    def list_commands(self, ctx):
        """Dynamically generate list of commands."""
        rv = []
        for filename in os.listdir(plugin_folder):
            if filename.endswith(".py") and not filename.startswith("__init__"):
                rv.append(filename[:-3])
        rv.sort()
        return rv

    def get_command(self, ctx, name):
        """Invoke command."""
        ns = {}
        try:
            fn = os.path.join(plugin_folder, name + ".py")
            with open(fn) as f:
                code = compile(f.read(), fn, "exec")
                eval(code, ns, ns)
            return ns["plugins"]
        except FileNotFoundError:
            click.echo("")
