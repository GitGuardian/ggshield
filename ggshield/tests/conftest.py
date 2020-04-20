from os.path import dirname, join, realpath

import vcr

my_vcr = vcr.VCR(
    cassette_library_dir=join(dirname(realpath(__file__)), "cassettes"),
    decode_compressed_response=True,
    ignore_localhost=True,
    match_on=["url", "method", "body"],
    serializer="yaml",
    record_mode="once",
    filter_headers=["Authorization"],
)
