from functools import partial, wraps

import click


# TODO - unsure if this is the right idiom
def catch_exception(func=None, *, handle):
    """catch exception decorator"""
    if not func:
        return partial(catch_exception, handle=handle)

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except handle as e:
            raise click.ClickException(e)

    return wrapper
