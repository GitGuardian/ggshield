import json
from pathlib import Path

from pyfakefs.fake_filesystem import FakeFilesystem

from ggshield.core.scan.id_cache import IDCache
from tests.unit.conftest import make_fake_path_inaccessible


def test_add(fs: FakeFilesystem):
    """
    GIVEN a cache instance
    WHEN add() is called
    THEN a cache file is created
    """
    cache_path = Path("/some_dir/cache.json")
    cache = IDCache(cache_path)

    some_id = "iam_an_id"
    cache.add(some_id)

    assert cache_path.exists()
    ids = json.loads(cache_path.read_text())
    assert ids == [some_id]


def test_contains(fs: FakeFilesystem):
    """
    GIVEN a cache file
    WHEN __contains__() is called
    THEN the response is what was expected
    """
    cache_path = Path("/some_dir/cache.json")
    some_id = "iam_an_id"

    # Create the file on the disk
    IDCache(cache_path).add(some_id)
    assert cache_path.exists()

    cache = IDCache(cache_path)
    assert some_id in cache
    assert "unknown_id" not in cache


def test_does_not_fail_if_cache_file_cannot_be_written(caplog, fs: FakeFilesystem):
    """
    GIVEN an instance of IDCache created for a path which cannot be created
    WHEN adding an entry
    THEN it does not raise an exception
    AND a log message is written
    """
    cache_path = Path("/some_dir/cache.json")
    cache_path.parent.mkdir()
    make_fake_path_inaccessible(fs, cache_path.parent)

    cache = IDCache(cache_path)
    cache.add("clean_id")
    log_record = caplog.records[0]
    assert log_record.levelname == "WARNING"
    assert "Failed to save" in log_record.message
    assert len(caplog.records) == 1


def test_does_not_fail_if_cache_file_cannot_be_read(caplog, fs: FakeFilesystem):
    """
    GIVEN a non-readable cache file
    WHEN an instance of IDCache is created using it
    THEN it does not crash
    AND a log message is written
    AND the cache can be queried
    """
    cache_path = Path("/some_dir/cache.json")
    cache_path.parent.mkdir()
    cache_path.write_text('["hello"]')
    make_fake_path_inaccessible(fs, cache_path)

    cache = IDCache(cache_path)
    log_record = caplog.records[0]
    assert log_record.levelname == "WARNING"
    assert "Failed to load" in log_record.message
    assert len(caplog.records) == 1

    assert "hello" not in cache
