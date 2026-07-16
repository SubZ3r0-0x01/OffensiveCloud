import os
import sys
import json
import hashlib
import hmac
import datetime
import logging
import urllib.parse
from typing import Optional, Dict, List, Any

import requests


logger = logging.getLogger(__name__)


# ------------------------------------------------------------------------------
# AWS Signature v4 signing utility
# ------------------------------------------------------------------------------

def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _get_signature_key(
    secret_key: str, date_stamp: str, region: str, service: str
) -> bytes:
    k_date = _sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    k_signing = _sign(k_service, "aws4_request")
    return k_signing


def sign_v4(
    method: str,
    service: str,
    region: str,
    endpoint: str,
    canonical_uri: str,
    canonical_querystring: str,
    headers: Dict[str, str],
    body: str,
    access_key: str,
    secret_key: str,
    session_token: Optional[str] = None,
) -> Dict[str, str]:
    """
    Sign an AWS request (Signature v4) and return the signed headers.
    """
    amz_date = headers.get("x-amz-date", "")
    date_stamp = amz_date[:8]  # YYYYMMDD

    # Create canonical request
    canonical_headers = "\n".join(
        [f"{k.lower()}:{v}" for k, v in sorted(headers.items())]
    )
    signed_headers = ";".join(sorted(headers.keys()))

    payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()

    canonical_request = (
        f"{method}\n"
        f"{canonical_uri}\n"
        f"{canonical_querystring}\n"
        f"{canonical_headers}\n"
        f"\n"
        f"{signed_headers}\n"
        f"{payload_hash}"
    )

    # Create string to sign
    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"

    string_to_sign = (
        f"{algorithm}\n"
        f"{amz_date}\n"
        f"{credential_scope}\n"
        f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
    )

    # Calculate signature
    signing_key = _get_signature_key(secret_key, date_stamp, region, service)
    signature = hmac.new(
        signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    # Build authorization header
    authorization_header = (
        f"{algorithm} Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    signed_headers = dict(headers)
    signed_headers["Authorization"] = authorization_header
    if session_token:
        signed_headers["X-Amz-Security-Token"] = session_token

    return signed_headers


def make_aws_request(
    access_key: str,
    secret_key: str,
    region: str,
    service: str,
    action: str,
    params: Optional[Dict[str, Any]] = None,
    session_token: Optional[str] = None,
    method: str = "POST",
) -> requests.Response:
    """
    Make a signed AWS API call to a given service.
    """
    if params is None:
        params = {}

    if method == "GET":
        # For GET, parameters go in query string
        canonical_querystring = urllib.parse.urlencode(params)
        body = ""
        payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    else:
        # POST with JSON body (default)
        body = json.dumps(params)
        payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        canonical_querystring = ""

    # Target headers for POST
    if service == "s3":
        # S3 uses virtual-hosted style
        endpoint = f"https://s3.{region}.amazonaws.com/"