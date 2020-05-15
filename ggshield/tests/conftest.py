from os.path import dirname, join, realpath

import vcr


my_vcr = vcr.VCR(
    cassette_library_dir=join(dirname(realpath(__file__)), "cassettes"),
    path_transformer=vcr.VCR.ensure_suffix(".yaml"),
    decode_compressed_response=True,
    ignore_localhost=True,
    match_on=["url", "method"],
    serializer="yaml",
    record_mode="once",
    filter_headers=["Authorization"],
)
