import json
import os

import pytest
import yaml

from ggshield.core.cache import Cache
from ggshield.core.config import Config
from ggshield.core.types import IgnoredMatch


@pytest.mark.usefixtures("isolated_fs")
class TestCache:
    def test_defaults(self):
        cache = Cache()
        assert cache.last_found_secrets == []

    def test_load_cache_and_purge(self):
        with open(".cache_ggshield", "w") as file:
            json.dump({"last_found_secrets": [{"name": "", "match": "XXX"}]}, file)
        cache = Cache()
        assert cache.last_found_secrets == [IgnoredMatch(name="", match="XXX")]

        cache.purge()
        assert cache.last_found_secrets == []

    def test_load_invalid_cache(self, capsys):
        with open(".cache_ggshield", "w") as file:
            json.dump({"invalid_option": True}, file)

        Cache()
        captured = capsys.readouterr()
        assert "Unrecognized key in cache" in captured.err

    def test_save_cache(self):
        with open(".cache_ggshield", "w") as file:
            json.dump({}, file)
        cache = Cache()
        cache.update_cache(last_found_secrets=[{"match": "XXX"}])
        cache.save()
        with open(".cache_ggshield") as file:
            file_content = json.load(file)
            assert file_content == {
                "last_found_secrets": [{"match": "XXX", "name": ""}]
            }

    def test_read_only_fs(self):
        """
        GIVEN a read-only cache file
        WHEN save is called
        THEN it shouldn't raise an exception
        """

        cache = Cache()
        cache.update_cache(last_found_secrets=[{"match": "XXX"}])

        # Make cache file read-only and verify it really is read-only
        cache.cache_path.touch(mode=0o400)
        with pytest.raises(PermissionError):
            cache.cache_path.open("w")

        cache.save()

    @pytest.mark.parametrize("with_entry", [True, False])
    def test_save_cache_first_time(self, isolated_fs, with_entry):
        """
        GIVEN no existing cache
        WHEN save is called but there are (new entries/no entries in memory)
        THEN it should (create/not create) the file
        """
        cache = Cache()
        if with_entry:
            cache.update_cache(last_found_secrets=[{"match": "XXX"}])
        cache.save()

        assert os.path.isfile(".cache_ggshield") is with_entry

    def test_max_commits_for_hook_setting(self):
        """
        GIVEN a yaml config with `max-commits-for-hook=75`
        WHEN the config gets parsed
        THEN the default value of max_commits_for_hook (50) should be replaced with 75
        """
        with open(".gitguardian.yml", "w") as file:
            file.write(yaml.dump({"max-commits-for-hook": 75}))

        config = Config()
        assert config.user_config.max_commits_for_hook == 75
