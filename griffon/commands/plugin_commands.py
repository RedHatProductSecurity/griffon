"""

"""
import logging
import os

import click

from griffon import get_config_option

logger = logging.getLogger("griffon")

plugin_folder = os.path.join(os.path.dirname(__file__), "plugins")

custom_plugin_dir = get_config_option("default", "custom_plugin_dir", "~/.griffon/plugins/")
custom_folder = os.path.dirname(os.path.expanduser(custom_plugin_dir))


class plugin_commands(click.MultiCommand):
    def list_commands(self, ctx):
        """Dynamically generate list of commands."""
        rv = []
        for filename in os.listdir(plugin_folder):
            if filename.endswith(".py") and not filename.startswith("__init__"):
                rv.append(filename[:-3])
        try:
            for filename in os.listdir(custom_folder):
                if filename.endswith(".py") and not filename.startswith("__init__"):
                    rv.append(filename[:-3])
        except FileNotFoundError:
            click.echo("")
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
            try:
                fn = os.path.join(custom_folder, name + ".py")
                with open(fn) as f:
                    code = compile(f.read(), fn, "exec")
                    eval(code, ns, ns)
                return ns["plugins"]
            except FileNotFoundError:
                logger.warning("plugin does not exist.")
