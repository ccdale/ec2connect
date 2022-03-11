"""Test functions for ec2connect/connect.py"""

import os

from ec2connect.connect import mkSession


def test_mkSession_no_env():
    """tests that mkSession uses the default profile"""
    sess = mkSession()
    assert sess.profile_name == "default"


def test_mkSession_with_profile():
    """tests that mkSession can set the profile"""
    sess = mkSession(profile="experiments-sre")
    assert sess.profile_name == "experiments-sre"


def test_mkSession_set_region():
    """tests that mkSession can set the region"""
    sess = mkSession(region="eu_west_3")
    assert sess.region_name == "eu_west_3"


def test_mkSession_env_override():
    """tests that mkSession doesn't overwrite the environment if set"""
    os.environ["AWS_PROFILE"] = "wibble"
    sess = mkSession(profile="experiments-sre")
    assert sess.profile_name == "wibble"
