from pathlib import Path
from typing import Optional, Pattern, Set, cast

import click
from pygitguardian import GGClient

from ggshield.cmd.utils.output_format import OutputFormat
from ggshield.core.cache import Cache
from ggshield.core.config import Config


class ContextObj:
    """This object is used as Click "context object": the object accessible via
    `ctx.obj`.

    While it is possible to use `ctx.obj` directly, it's better to write:

    ```
    ctx_obj = ContextObj.get(ctx)
    ```

    Doing so ensures the type checker knows `ctx_obj` is an instance of
    ContextObj and can verify access to member variables, whereas when using
    `ctx.obj` directly, the type checker considers it to be of type `Any`.

    Some attributes (`config`, `client` and `cache`) are implemented as
    properties. These properties check the attribute has been set before
    returning it. This allows the class to store instance `foo` as
    `Optional[Foo]` but exposing it as `Foo`.
    """

    def __init__(self):
        self._config: Optional[Config] = None
        self._client: Optional[GGClient] = None
        self._cache: Optional[Cache] = None

        # Depending on the vertical, this is set by configuration options or
        # command-line parameters
        self.exclusion_regexes: Set[Pattern[str]] = set()

        # Set to false by the --no-check-for-updates option
        self.check_for_updates = True

        self.output_format = OutputFormat.TEXT

        # Set by the --output option
        self.output: Optional[Path] = None

    @property
    def use_json(self) -> bool:
        return self.output_format == OutputFormat.JSON

    @property
    def config(self) -> Config:
        assert self._config
        return self._config

    @config.setter
    def config(self, value: Config) -> None:
        self._config = value

    @property
    def client(self) -> GGClient:
        assert self._client
        return self._client

    @client.setter
    def client(self, value: GGClient) -> None:
        self._client = value

    @property
    def cache(self) -> Cache:
        assert self._cache
        return self._cache

    @cache.setter
    def cache(self, value: Cache) -> None:
        self._cache = value

    @staticmethod
    def get(ctx: click.Context) -> "ContextObj":
        """The recommended way to get a ContextObj instance, see the class docstring for
        details"""
        assert ctx.obj
        return cast(ContextObj, ctx.obj)
