"""
Custom defined Click commands/options/etc.
"""

import click

from griffon.exceptions import GriffonUsageError
from griffon.helpers import Style


class ListParamType(click.ParamType):
    """Custom comma-separated list type"""

    name = "list"

    def convert(self, value, param, ctx):
        if value is None:
            return []
        return value.split(",")


class BaseGroupParameter:
    """
    Custom base parameter which handles:
        * mutually exclusive options
        * required group options (one of the group is required)
    """

    def handle_parse_result(self, ctx, opts, args):
        if not ctx.resilient_parsing:
            if self.mutually_exclusive_group:
                if opts.get(self.name) is None:
                    pass  # skip check for not supplied click.Arguments
                elif self.name in opts and any(
                    opt in opts
                    for opt in self.mutually_exclusive_group
                    if opts.get(opt) is not None
                ):
                    raise GriffonUsageError(
                        (
                            f"{Style.BOLD}{self.name} cannot be used with "
                            f"{', '.join(self.mutually_exclusive_group)}.{Style.RESET}"
                        ),
                        ctx=ctx,
                    )

            if self.required_group:
                group_set = set(
                    opt for opt in opts if opt in self.required_group and opts.get(opt) is not None
                )
                if not any(group_set):
                    raise GriffonUsageError(
                        f"{Style.BOLD}At least one of {', '.join(self.required_group)} "
                        f"is required.{Style.RESET}",
                        ctx=ctx,
                    )

        return super().handle_parse_result(ctx, opts, args)


class GroupOption(BaseGroupParameter, click.Option):
    """Custom Option with BaseGroupParameter functionality"""

    def __init__(self, *args, **kwargs):
        self.mutually_exclusive_group = set(kwargs.pop("mutually_exclusive_group", []))
        self.required_group = set(kwargs.pop("required_group", []))

        if self.mutually_exclusive_group:
            mutually_exclusive_str = ", ".join(self.mutually_exclusive_group)
            kwargs["help"] = kwargs.get("help", "") + (
                f", this argument is mutually exclusive "
                f"with arguments: {Style.BOLD}[{mutually_exclusive_str}]{Style.RESET}"
            )

        if self.required_group:
            required_str = ", ".join(self.required_group)
            kwargs["help"] = kwargs.get("help", "") + (
                f", at least one of these arguments: "
                f"{Style.BOLD}[{required_str}]{Style.RESET} is required."
            )

        super().__init__(*args, **kwargs)


class GroupArgument(BaseGroupParameter, click.Argument):
    """Custom Argument with BaseGroupParameter functionality"""

    def __init__(self, *args, **kwargs):
        self.mutually_exclusive_group = set(kwargs.pop("mutually_exclusive_group", []))
        self.required_group = set(kwargs.pop("required_group", []))

        super().__init__(*args, **kwargs)
