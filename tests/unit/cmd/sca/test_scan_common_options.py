import click

from ggshield.cmd.sca.scan.scan_common_options import update_context
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.config import Config
from ggshield.core.ui.plain_text.plain_text_ggshield_ui import PlainTextGGShieldUI


def test_update_context():
    """
    GIVEN some parameters
    WHEN calling update context from sca
    THEN those parameters are given to the SCAUserConfig
    """
    # Create click context
    config = Config()
    config.user_config.verbose = False
    ctx_obj = ContextObj()
    ctx_obj.config = config
    ctx_obj.ui = PlainTextGGShieldUI()
    ctx = click.Context(
        click.Command("sca scan all"),
        obj=ctx_obj,
    )

    assert ctx_obj.config.user_config.sca.minimum_severity == "LOW"
    assert ctx_obj.config.user_config.exit_zero is False
    assert ctx_obj.config.user_config.sca.ignored_paths == {"tests/"}
    assert ctx_obj.config.user_config.sca.ignore_fixable is False
    assert ctx_obj.config.user_config.sca.ignore_not_fixable is False

    update_context(
        ctx,
        exit_zero=True,
        minimum_severity="HIGH",
        ignore_paths=[],
        ignore_fixable=True,
        ignore_not_fixable=False,
    )

    ctx_obj = ContextObj.get(ctx)

    assert ctx_obj.config.user_config.sca.minimum_severity == "HIGH"
    assert ctx_obj.config.user_config.exit_zero is True
    assert ctx_obj.config.user_config.sca.ignored_paths == {"tests/"}
    assert ctx_obj.config.user_config.sca.ignore_fixable is True
    assert ctx_obj.config.user_config.sca.ignore_not_fixable is False
