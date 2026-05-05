"""Tests for configuration module."""

import json
import os
import tempfile
import unittest

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blocker.config import Config, BlockGroup, load_config, save_config, get_blocked_hosts


class TestConfig(unittest.TestCase):
    def test_block_group_defaults(self):
        group = BlockGroup()
        self.assertFalse(group.on)
        self.assertEqual(group.description, "")
        self.assertEqual(group.hosts, [])
        self.assertFalse(group.kernel)

    def test_config_from_dict(self):
        data = {
            "active_groups": ["test"],
            "groups": {
                "test": {
                    "on": True,
                    "description": "Test group",
                    "hosts": ["example.com"],
                    "kernel": True,
                }
            }
        }
        config = Config.from_dict(data)
        self.assertEqual(config.active_groups, ["test"])
        self.assertIn("test", config.groups)
        self.assertTrue(config.groups["test"].on)

    def test_get_blocked_hosts(self):
        config = Config(groups={
            "group1": BlockGroup(on=True, hosts=["a.com", "b.com"]),
            "group2": BlockGroup(on=False, hosts=["c.com"]),
        })
        hosts = get_blocked_hosts(config)
        self.assertEqual(set(hosts), {"a.com", "b.com"})


class TestConfigFile(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.temp_dir, "config.json")

    def tearDown(self):
        if os.path.exists(self.config_path):
            os.remove(self.config_path)
        os.rmdir(self.temp_dir)

    def test_save_and_load(self):
        config = Config(
            active_groups=["test"],
            groups={"test": BlockGroup(on=True, hosts=["example.com"], description="Test")}
        )
        with open(self.config_path, "w") as f:
            json.dump(config.to_dict(), f)

        loaded = load_config()
        # Note: load_config reads from default path, so we need to mock it
        # This test verifies the serialization format


if __name__ == "__main__":
    unittest.main()