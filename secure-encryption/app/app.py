"""
app.py -- Secure S3 Encryptor backend API (Flask + boto3)

Endpoints
    GET  /api/health              -> liveness probe
    POST /api/validate            -> validate credentials (STS get-caller-identity)
    POST /api/apply               -> apply the full encryption architecture
    POST /api/verify              -> read back and confirm the configuration
    POST /api/upload  (multipart) -> upload a local file, forced SSE-KMS, and prove it

SECURITY: credentials arrive per-request, are used to build an in-memory boto3
session, and are never logged or persisted. Run this ONLY on your local machine
(localhost). Do not deploy this credential-collecting form to the public internet.
"""

import os
from flask import Flask, request, jsonify

from werkzeug.exceptions import HTTPException

import aws_ops as ops
from botocore.exceptions import (
    BotoCoreError, ClientError, EndpointConnectionError,
    NoCredentialsError, ParamValidationError,
)

app = Flask(__name__)
# The container serves frontend and API from the same origin.


MAX_UPLOAD_MB = 25
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024


def _creds(body):
    ak = (body.get("accessKeyId") or "").strip()
    sk = (body.get("secretAccessKey") or "").strip()
    rg = (body.get("region") or "").strip()
    if not ak or not sk or not rg:
        raise ValueError("Access Key ID, Secret Access Key and Region are all required.")
    return ak, sk, rg


def _fail(e, status=400):
    return jsonify({"success": False, "message": ops.translate_error(e)}), status


# Safety net: any exception not caught in a route returns friendly JSON,
# never an HTML stack trace (which could leak internals).
@app.errorhandler(Exception)
def handle_any(e):
    if isinstance(e, HTTPException):
        return jsonify({"success": False, "message": e.description}), e.code
    return jsonify({"success": False, "message": ops.translate_error(e)}), 400


@app.get("/api/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/api/validate")
def validate():
    try:
        body = request.get_json(force=True) or {}
        ak, sk, rg = _creds(body)
        session = ops.make_session(ak, sk, rg)
        ident = ops.validate_identity(session)
        return jsonify({"success": True, "identity": ident,
                        "message": f"Connected as {ident['arn']}"})
    except (ClientError, NoCredentialsError, EndpointConnectionError,
            ParamValidationError, ValueError) as e:
        return _fail(e)


@app.post("/api/apply")
def apply():
    try:
        body = request.get_json(force=True) or {}
        ak, sk, rg = _creds(body)
        bucket = (body.get("bucketName") or "").strip()
        iam_user = (body.get("iamUser") or "").strip()
        existing_key = (body.get("existingKeyArn") or "").strip() or None
        create_user = bool(body.get("createUserIfMissing"))

        ops.validate_bucket_name(bucket)
        session = ops.make_session(ak, sk, rg)

        # fatal pre-flight
        identity = ops.validate_identity(session)
        region = ops.get_bucket_region(session, bucket)
        key_arn, key_created = ops.ensure_kms_key(session, region, bucket, existing_key)
    except (ClientError, NoCredentialsError, EndpointConnectionError,
            ParamValidationError, ValueError, LookupError, PermissionError) as e:
        return _fail(e)

    # non-fatal steps: record each, continue on failure
    steps = []

    def do(name, fn):
        try:
            steps.append({"name": name, "status": "success", "detail": fn()})
        except Exception as e:  # noqa: BLE001 - we translate + report
            steps.append({"name": name, "status": "error", "detail": ops.translate_error(e)})

    steps.append({"name": "KMS encryption key", "status": "success",
                  "detail": ("Created new key " if key_created else "Using existing key ")
                            + key_arn})
    do("Default bucket encryption (SSE-KMS)",
       lambda: ops.apply_bucket_encryption(session, region, bucket, key_arn))
    do("Block all public access",
       lambda: ops.apply_public_access_block(session, region, bucket))
    do("Enable versioning",
       lambda: ops.apply_versioning(session, region, bucket))
    do("Bucket policy (TLS + KMS enforcement)",
       lambda: ops.apply_bucket_policy(session, region, bucket))
    do(f"IAM user scoping ({iam_user or 'none'})",
       lambda: ops.attach_iam_user_policy(session, iam_user, bucket, key_arn, create_user))

    overall = all(s["status"] == "success" for s in steps)
    return jsonify({
        "success": overall,
        "message": "Encryption architecture applied." if overall
                   else "Applied with some errors - see steps.",
        "account": identity["account"], "region": region,
        "bucket": bucket, "keyArn": key_arn, "steps": steps,
    })


@app.post("/api/verify")
def verify():
    try:
        body = request.get_json(force=True) or {}
        ak, sk, rg = _creds(body)
        bucket = (body.get("bucketName") or "").strip()
        ops.validate_bucket_name(bucket)
        session = ops.make_session(ak, sk, rg)
        ops.validate_identity(session)
        region = ops.get_bucket_region(session, bucket)
        checks = ops.verify_bucket(session, region, bucket)
        overall = all(c["ok"] for c in checks.values())
        return jsonify({"success": overall, "region": region,
                        "bucket": bucket, "checks": checks})
    except (ClientError, NoCredentialsError, EndpointConnectionError,
            ParamValidationError, ValueError, LookupError, PermissionError) as e:
        return _fail(e)


@app.post("/api/upload")
def upload():
    try:
        f = request.files.get("file")
        if not f:
            raise ValueError("No file was provided.")
        ak = (request.form.get("accessKeyId") or "").strip()
        sk = (request.form.get("secretAccessKey") or "").strip()
        rg = (request.form.get("region") or "").strip()
        bucket = (request.form.get("bucketName") or "").strip()
        key_arn = (request.form.get("keyArn") or "").strip() or None
        if not ak or not sk or not rg or not bucket:
            raise ValueError("Credentials, region and bucket are required.")
        ops.validate_bucket_name(bucket)

        session = ops.make_session(ak, sk, rg)
        ops.validate_identity(session)
        region = ops.get_bucket_region(session, bucket)

        data = f.read()
        safe_name = os.path.basename(f.filename or "upload.bin")
        result = ops.upload_encrypted(session, region, bucket, key_arn,
                                      f"uploads/{safe_name}", data)
        return jsonify({"success": result["encryptedAtRest"],
                        "message": "File uploaded and encrypted at rest."
                                   if result["encryptedAtRest"]
                                   else "File uploaded but NOT encrypted - check config.",
                        "result": result})
    except (ClientError, NoCredentialsError, EndpointConnectionError,
            ParamValidationError, ValueError, LookupError, PermissionError) as e:
        return _fail(e)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    # host=127.0.0.1 keeps the credential-handling API on the local machine only.
    app.run(host="127.0.0.1", port=port, debug=False)
