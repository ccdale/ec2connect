"""Functions to use to connect to an EC2 instance."""

import os
import sys

import boto3

from ec2connect import errorNotify


def mkSession(profile=None, region=None):
    """Sets up the environment if necessary.

    Uses setdefault on the environment to not override
    any existing keys if they are already set.

    returns: boto3 session
    """
    try:
        if profile is not None:
            os.environ.setdefault("AWS_PROFILE", profile)
        if region is not None:
            os.environ.setdefault("AWS_DEFAULT_REGION", region)
        return boto3.session.Session()
    except Exception as e:
        errorNotify(sys.exc_info()[2], e)


def mkClient(ctype="ec2", profile=None, region=None, config=None):
    """Returns a boto3 client of type ctype"""
    try:
        kwargs = {"profile": profile, "region": region}
        sess = mkSession(**kwargs)
        return sess.client(ctype, config=config)
    except Exception as e:
        errorNotify(sys.exc_info()[2], e)


def mkResource(rtype="ec2", profile=None, region=None, config=None):
    """Returns a boto3 resource of type rtype"""
    try:
        kwargs = {"profile": profile, "region": region}
        sess = mkSession(**kwargs)
        return sess.Resource(rtype, config=config)
    except Exception as e:
        errorNotify(sys.exc_info()[2], e)
