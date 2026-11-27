"""
aws_ops.py
==========
All boto3 / AWS logic for the Secure S3 Encryptor.

Design notes (Cloud Security Architect):
- A fresh boto3 Session is built PER REQUEST from the credentials the user
  supplies. Nothing is cached, logged, or written to disk.
- Bucket operations are performed with an S3 client pinned to the BUCKET'S OWN
  region (discovered at runtime), because SSE-KMS requires the KMS key and the
  bucket to live in the same region.
- Every AWS ClientError is translated into a short, human-readable message so
  the frontend can show something useful instead of a raw stack trace.
"""

import json
import re
import secrets
import boto3
from botocore.exceptions import (
    ClientError, EndpointConnectionError, NoCredentialsError, ParamValidationError,
)

BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")


# --------------------------------------------------------------------------- #
# Session + validation
# --------------------------------------------------------------------------- #
def make_session(access_key, secret_key, region):
    return boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )


def validate_identity(session):
    """Confirm the credentials work. Returns {account, arn, userId}."""
    sts = session.client("sts")
    ident = sts.get_caller_identity()
    return {"account": ident["Account"], "arn": ident["Arn"], "userId": ident["UserId"]}


def validate_bucket_name(name):
    if not name or not BUCKET_RE.match(name):
        raise ValueError(
            "Invalid S3 bucket name. Use 3-63 chars: lowercase letters, "
            "numbers, dots and hyphens; must start/end alphanumeric."
        )


# --------------------------------------------------------------------------- #
# Region discovery + existence
# --------------------------------------------------------------------------- #
def get_bucket_region(session, bucket):
    """Return the bucket's region, raising a clear error if it does not exist
    or is not accessible with these credentials."""
    s3 = session.client("s3")
    try:
        s3.head_bucket(Bucket=bucket)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("404", "NoSuchBucket"):
            raise LookupError(f"Bucket '{bucket}' was not found in this account.")
        if code in ("403", "AccessDenied"):
            raise PermissionError(
                f"Bucket '{bucket}' exists but these credentials cannot access it."
            )
        # 301 == wrong region for this client, but head still tells us the region below
        if code != "301":
            raise
    loc = s3.get_bucket_location(Bucket=bucket).get("LocationConstraint")
    if loc in (None, ""):
        return "us-east-1"
    if loc == "EU":
        return "eu-west-1"
    return loc


def s3_for(session, region):
    return session.client("s3", region_name=region)


# --------------------------------------------------------------------------- #
# KMS key
# --------------------------------------------------------------------------- #
def ensure_kms_key(session, region, bucket, existing_arn=None):
    """Reuse an existing key ARN if supplied, else create a customer-managed
    CMK in the bucket's region. Returns (key_arn, created_bool)."""
    kms = session.client("kms", region_name=region)
    if existing_arn:
        kms.describe_key(KeyId=existing_arn)  # validates it exists / is usable
        return existing_arn, False

    resp = kms.create_key(
        Description=f"Data-at-rest encryption key for S3 bucket {bucket}",
        Tags=[{"TagKey": "Project", "TagValue": "SecureS3Encryptor"}],
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    key_arn = resp["KeyMetadata"]["Arn"]
    # best-effort alias (ignore collisions)
    safe = re.sub(r"[^a-zA-Z0-9_-]", "-", bucket)[:40]
    alias = f"alias/secure-s3-{safe}-{secrets.token_hex(2)}"
    try:
        kms.create_alias(AliasName=alias, TargetKeyId=key_id)
    except ClientError:
        pass
    return key_arn, True


# --------------------------------------------------------------------------- #
# The encryption architecture (applied to the target bucket)
# --------------------------------------------------------------------------- #
def apply_bucket_encryption(session, region, bucket, key_arn):
    s3 = s3_for(session, region)
    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [{
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": key_arn,
                },
                "BucketKeyEnabled": True,
            }]
        },
    )
    return "Default SSE-KMS encryption enabled with the customer-managed key."


def apply_public_access_block(session, region, bucket):
    s3 = s3_for(session, region)
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
    )
    return "All four public-access-block settings enabled."


def apply_versioning(session, region, bucket):
    s3 = s3_for(session, region)
    s3.put_bucket_versioning(
        Bucket=bucket, VersioningConfiguration={"Status": "Enabled"}
    )
    return "Object versioning enabled."


def apply_bucket_policy(session, region, bucket):
    s3 = s3_for(session, region)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyInsecureTransport",
                "Effect": "Deny", "Principal": "*", "Action": "s3:*",
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            },
            {
                "Sid": "DenyUnEncryptedObjectUploads",
                "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {"StringNotEquals": {"s3:x-amz-server-side-encryption": "aws:kms"}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    return "Bucket policy applied (deny non-TLS + deny non-KMS uploads)."


def attach_iam_user_policy(session, username, bucket, key_arn, create_if_missing=False):
    if not username:
        return "Skipped (no IAM user supplied)."
    iam = session.client("iam")
    try:
        iam.get_user(UserName=username)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            if create_if_missing:
                iam.create_user(UserName=username,
                                Tags=[{"Key": "Project", "Value": "SecureS3Encryptor"}])
            else:
                raise LookupError(
                    f"IAM user '{username}' does not exist "
                    "(tick 'create if missing' to create it)."
                )
        else:
            raise
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow",
             "Action": ["s3:PutObject", "s3:GetObject", "s3:ListBucket"],
             "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]},
            {"Effect": "Allow",
             "Action": ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"],
             "Resource": key_arn},
        ],
    }
    iam.put_user_policy(UserName=username, PolicyName="SecureS3Access",
                        PolicyDocument=json.dumps(doc))
    return f"Least-privilege policy attached to IAM user '{username}'."


# --------------------------------------------------------------------------- #
# Verification + data upload (laptop -> cloud, encrypted)
# --------------------------------------------------------------------------- #
def verify_bucket(session, region, bucket):
    s3 = s3_for(session, region)
    result = {}

    try:
        enc = s3.get_bucket_encryption(Bucket=bucket)
        rule = enc["ServerSideEncryptionConfiguration"]["Rules"][0]["ApplyServerSideEncryptionByDefault"]
        result["encryption"] = {"ok": rule["SSEAlgorithm"] == "aws:kms",
                                "detail": f"{rule['SSEAlgorithm']} ({rule.get('KMSMasterKeyID','-')})"}
    except ClientError as e:
        result["encryption"] = {"ok": False, "detail": translate_error(e)}

    try:
        s3.get_bucket_policy(Bucket=bucket)
        result["policy"] = {"ok": True, "detail": "Bucket policy present."}
    except ClientError as e:
        result["policy"] = {"ok": False, "detail": translate_error(e)}

    try:
        pab = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        result["publicAccessBlock"] = {"ok": all(pab.values()), "detail": json.dumps(pab)}
    except ClientError as e:
        result["publicAccessBlock"] = {"ok": False, "detail": translate_error(e)}

    try:
        ver = s3.get_bucket_versioning(Bucket=bucket).get("Status", "Disabled")
        result["versioning"] = {"ok": ver == "Enabled", "detail": ver}
    except ClientError as e:
        result["versioning"] = {"ok": False, "detail": translate_error(e)}

    return result


def upload_encrypted(session, region, bucket, key_arn, key_name, data_bytes):
    """Upload bytes from the local machine, forcing SSE-KMS, then read the
    stored object's metadata back to PROVE it is encrypted at rest."""
    s3 = s3_for(session, region)
    put_args = {"Bucket": bucket, "Key": key_name, "Body": data_bytes,
                "ServerSideEncryption": "aws:kms"}
    if key_arn:
        put_args["SSEKMSKeyId"] = key_arn
    s3.put_object(**put_args)
    head = s3.head_object(Bucket=bucket, Key=key_name)
    return {
        "key": key_name,
        "size": len(data_bytes),
        "serverSideEncryption": head.get("ServerSideEncryption"),
        "kmsKeyId": head.get("SSEKMSKeyId"),
        "encryptedAtRest": head.get("ServerSideEncryption") == "aws:kms",
    }


# --------------------------------------------------------------------------- #
# Error translation
# --------------------------------------------------------------------------- #
def translate_error(e):
    if isinstance(e, NoCredentialsError):
        return "No AWS credentials were provided."
    if isinstance(e, EndpointConnectionError):
        return "Could not reach AWS. Check the region and your internet connection."
    if isinstance(e, ParamValidationError):
        return f"Invalid parameter: {e}"
    if isinstance(e, (ValueError, LookupError, PermissionError)):
        return str(e)
    if isinstance(e, ClientError):
        code = e.response["Error"].get("Code", "Unknown")
        msg = e.response["Error"].get("Message", "")
        mapping = {
            "InvalidAccessKeyId": "The AWS Access Key ID is not valid.",
            "SignatureDoesNotMatch": "The AWS Secret Access Key is not valid.",
            "UnrecognizedClientException": "The AWS credentials are not recognized.",
            "InvalidClientTokenId": "The AWS credentials are invalid or disabled.",
            "AccessDenied": f"Access denied. The credentials lack a required permission. ({msg})",
            "AccessDeniedException": f"Access denied. ({msg})",
            "NoSuchBucket": "The target S3 bucket does not exist.",
            "NoSuchEntity": "The IAM user was not found.",
            "KMSInvalidStateException": "The KMS key is not in a usable state.",
        }
        return mapping.get(code, f"{code}: {msg}")
    return str(e)
