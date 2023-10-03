# Custom plugins

Plugins are picked up dynamically.

Each plugin is represented by a single Python file (`.py` extension) which contains
function `plugins` decorated with `click.group` which is a Griffon plugin bare minimum.

Each plugin needs to comply to the following bare minimum:
* single file with `.py` extension
* file contains function called `plugins` decorated with suitable `click` decorator (`click.group`, `click.command`, etc.)

See [example plugin](example.py) for the reference.
