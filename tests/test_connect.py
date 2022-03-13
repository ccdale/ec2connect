"""Test functions for ec2connect/connect.py"""

import os

from botocore.config import Config
from moto import mock_ec2
import pytest

from ec2connect.connect import mkSession

config = Config(
    region_name="eu-west-1",
    signature_version="v4",
    retries={"max_attempts": 10, "mode": "standard"},
)


@pytest.fixture(scope="function")
def aws_creds():
    """Mocked AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "eu_west_1"


def test_mkSession_no_env():
    """tests that mkSession uses the default profile"""
    sess = mkSession()
    assert sess.profile_name == "default"


def test_mkSession_with_profile():
    """tests that mkSession can set the profile

    relies on a profile of this name existing
    in either of the ~/.aws/{config, credentials} files

    it can be blank as in

    [experiments-sre]
    # blank profile

    """
    sess = mkSession(profile="experiments-sre")
    assert sess.profile_name == "experiments-sre"


def test_mkSession_set_region():
    """tests that mkSession can set the region"""
    sess = mkSession(region="eu_west_3")
    assert sess.region_name == "eu_west_3"


def test_mkSession_env_override():
    """tests that mkSession doesn't overwrite the environment if set

    ensure a 2nd blank profile called 'wibble' is also setup
    """
    os.environ["AWS_PROFILE"] = "wibble"
    sess = mkSession(profile="experiments-sre")
    assert sess.profile_name == "wibble"
