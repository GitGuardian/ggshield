from dataclasses import dataclass, field
from typing import List, Optional, Set

from ggshield.core.config.utils import replace_in_keys, update_from_other_instance


def test_replace_in_keys():
    data = {"last-found-secrets": {"XXX"}}
    replace_in_keys(data, "-", "_")
    assert data == {"last_found_secrets": {"XXX"}}
    replace_in_keys(data, "_", "-")
    assert data == {"last-found-secrets": {"XXX"}}


@dataclass
class ExampleSubConfig:
    an_int: Optional[int] = None
    an_str: Optional[str] = None


@dataclass
class ExampleConfig:
    path: Optional[str] = None
    backup: bool = True
    subconf: ExampleSubConfig = field(default_factory=ExampleSubConfig)
    a_list: List[str] = field(default_factory=list)
    a_set: Set[str] = field(default_factory=set)


def test_update_from_other_instance():
    """
    GIVEN two dataclass instances
    WHEN update_from_other_instance(dst_conf, src_conf) is called
    THEN dst_conf is updated from src_conf fields
    """

    dst_conf = ExampleConfig(path="dst_path")
    dst_conf.subconf.an_int = 1
    dst_conf.a_list = ["i1", "i2"]
    dst_conf.a_set = {"i1", "i2"}

    src_conf = ExampleConfig(backup=False)
    src_conf.subconf.an_str = "src_subconf_str"
    src_conf.a_list = ["i2", "i3"]
    src_conf.a_set = {"i2", "i3"}

    update_from_other_instance(dst_conf, src_conf)

    assert dst_conf.path == "dst_path"
    assert dst_conf.backup is False
    assert dst_conf.subconf.an_int == 1
    assert dst_conf.subconf.an_str == "src_subconf_str"
    assert dst_conf.a_list == ["i1", "i2", "i2", "i3"]
    assert dst_conf.a_set == {"i1", "i2", "i3"}
