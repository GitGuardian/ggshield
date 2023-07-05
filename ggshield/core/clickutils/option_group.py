from typing import Any, List, Mapping

import click


# All options subscribed form a group
# One of them must be present (and no more)


class OptionGroup(click.Option):
    def __init__(self, *args: Any, **kwargs: Any):
        self.not_required_if: List[str] = kwargs.pop("not_required_if")

        assert self.not_required_if, "'not_required_if' parameter required"
        kwargs["help"] = (
            kwargs.get("help", "")
            + " "
            + "Option is mutually exclusive with "
            + ", ".join(self.not_required_if)
            + "."
        ).strip()
        super().__init__(*args, **kwargs)

    def handle_parse_result(
        self, ctx: click.Context, opts: Mapping[str, Any], args: List[str]
    ) -> Any:
        current_opt: bool = self.name in opts
        has_one = current_opt

        for mutex_opt in self.not_required_if:
            if mutex_opt.replace("-", "_") in opts:
                has_one = True
                if current_opt:
                    raise click.UsageError(
                        "Illegal usage: '"
                        + str(self.name)
                        + "' is mutually exclusive with "
                        + str(mutex_opt)
                        + "."
                    )
                else:
                    self.prompt = None
        if not (has_one):
            group = self.not_required_if.copy()
            if self.name:
                group.append(self.name)
            raise click.UsageError(
                "One of the following options must be used: " + ", ".join(group)
            )
        return super().handle_parse_result(ctx, opts, args)
