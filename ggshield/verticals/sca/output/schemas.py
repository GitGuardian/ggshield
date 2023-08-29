from ggshield.verticals.sca.sca_scan_models import (
    SCAScanAllOutputSchema,
    SCAScanDiffOutputSchema,
)


class SCAJSONScanAllOutputSchema(SCAScanAllOutputSchema):
    total_vulns: int


class SCAJSONScanDiffOutputSchema(SCAScanDiffOutputSchema):
    total_vulns: int
