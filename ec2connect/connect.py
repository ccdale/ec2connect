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
        return boto3.Session()
    except Exception as e:
        errorNotify(sys.exc_info()[2], e)


def mkClient(sess, ctype="ec2"):
    try:
        client = sess.client(ctype)
        pass
    except Exception as e:
        errorNotify(sys.exc_info()[2], e)
