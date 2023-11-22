"""
Griffon exceptions and exception handling

TODO: eventually we will want to gracefully handle all errors
though useful during development to 'see' everything.
"""

from functools import partial, wraps

import click

from griffon.helpers import Color, Style


class GriffonException(click.ClickException):
    """Base Griffon exception"""

    def __init__(self, message, *args, **kwargs) -> None:
        super().__init__(f"{Style.BOLD}{Color.RED}{message}{Color.RESET}", *args, **kwargs)

    def show(self, *args, **kwargs):
        click.echo((f"{Style.BOLD}{Color.RED}{' Griffon Error ':*^55}{Style.RESET}"))
        super().show(*args, **kwargs)


class GriffonUsageError(GriffonException, click.UsageError):
    """Griffon exception that signals a usage error"""

    pass


def catch_exception(func=None, *, handle):
    """catch exception decorator"""
    if not func:
        return partial(catch_exception, handle=handle)

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except handle as e:
            raise click.GriffonException(e)

    return wrapper
