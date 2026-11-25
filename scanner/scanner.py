#!/usr/bin/env python3
"""Mini cloud-security-posture scanner for a local AWS emulator (Floci).

Checks S3 buckets and IAM roles whose names start with --prefix, reports findings,
and with --fix applies the safe remediation for each one. Optionally publishes an
alert (SNS) and writes log lines (CloudWatch Logs) so a metric filter/alarm can fire.

Deliberately simple heuristics - see README "Limitations". Not a substitute for
Prowler / AWS Config / Security Hub on a real account.
"""
import argparse
import json
import os
import sys
import time
from urllib.parse import unquote

import boto3
from botocore.exceptions import ClientError

ENDPOINT = os.environ.get("AWS_ENDPOINT_URL", "http://localhost:4566")
REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
PUBLIC_GROUPS = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)


def client(name):
    return boto3.client(name, endpoint_url=ENDPOINT, region_name=REGION)


def err_code(e):
    return e.response.get("Error", {}).get("Code", "")


def as_list(x):
    return x if isinstance(x, list) else ([] if x is None else [x])


def call_or_none(fn, *ok_codes, **kw):
    """Run an API call; return None if it fails with one of the 'not configured' error codes."""
    try:
        return fn(**kw)
    except ClientError as e:
        if err_code(e) in ok_codes:
            return None
        raise


def finding(fid, sev, resource, detail, fix):
    return {"id": fid, "severity": sev, "resource": resource, "detail": detail, "fix": fix}


# ---------------------------------------------------------------- S3 checks
def is_public_statement(st):
    if st.get("Effect") != "Allow" or st.get("Condition"):
        return False  # conditioned statements may be narrowed; heuristic skips them (limitation)
    p = st.get("Principal")
    return p == "*" or (isinstance(p, dict) and "*" in as_list(p.get("AWS")))


def scan_bucket(s3, b, kms_key):
    res, out = f"s3://{b}", []

    r = call_or_none(s3.get_bucket_policy, "NoSuchBucketPolicy", Bucket=b)
    if r:
        doc = json.loads(r["Policy"])
        if any(is_public_statement(s) for s in as_list(doc.get("Statement"))):
            out.append(finding("S3-PUBLIC-POLICY", "HIGH", res,
                               "bucket policy grants access to a wildcard principal",
                               lambda: s3.delete_bucket_policy(Bucket=b)))

    acl = s3.get_bucket_acl(Bucket=b)
    if any(g.get("Grantee", {}).get("URI") in PUBLIC_GROUPS for g in acl.get("Grants", [])):
        out.append(finding("S3-PUBLIC-ACL", "HIGH", res, "ACL grants access to AllUsers/AuthenticatedUsers",
                           lambda: s3.put_bucket_acl(Bucket=b, ACL="private")))

    pab = call_or_none(s3.get_public_access_block, "NoSuchPublicAccessBlockConfiguration", Bucket=b)
    cfg = (pab or {}).get("PublicAccessBlockConfiguration", {})
    if not all(cfg.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
        out.append(finding("S3-NO-PUBLIC-ACCESS-BLOCK", "HIGH", res,
                           "Block Public Access is missing or not fully enabled",
                           lambda: s3.put_public_access_block(Bucket=b, PublicAccessBlockConfiguration={
                               "BlockPublicAcls": True, "IgnorePublicAcls": True,
                               "BlockPublicPolicy": True, "RestrictPublicBuckets": True})))

    # Every new S3 bucket is SSE-S3 (AES256) encrypted by default, so the useful check is
    # "does it use a customer-managed KMS key" (own key policy, audit trail, revocable).
    enc = call_or_none(s3.get_bucket_encryption, "ServerSideEncryptionConfigurationNotFoundError", Bucket=b)
    algos = [r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
             for r in (enc or {}).get("ServerSideEncryptionConfiguration", {}).get("Rules", [])]
    if "aws:kms" not in algos:
        def fix_enc():
            if not kms_key:
                raise RuntimeError("needs --kms-key-id")
            s3.put_bucket_encryption(Bucket=b, ServerSideEncryptionConfiguration={"Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": kms_key}}]})
        out.append(finding("S3-NO-KMS-ENCRYPTION", "MEDIUM", res,
                           "default encryption is not a customer-managed KMS key (SSE-S3 only)", fix_enc))

    if s3.get_bucket_versioning(Bucket=b).get("Status") != "Enabled":
        out.append(finding("S3-NO-VERSIONING", "LOW", res, "versioning is not enabled",
                           lambda: s3.put_bucket_versioning(Bucket=b, VersioningConfiguration={"Status": "Enabled"})))
    return out


# ---------------------------------------------------------------- IAM checks
def scan_role(iam, name):
    res, out = f"iam:role/{name}", []
    for pn in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        doc = iam.get_role_policy(RoleName=name, PolicyName=pn)["PolicyDocument"]
        if isinstance(doc, str):
            doc = json.loads(unquote(doc))
        for st in as_list(doc.get("Statement")):
            if st.get("Effect") == "Allow" and "*" in as_list(st.get("Action")):
                out.append(finding("IAM-WILDCARD-ACTION", "HIGH", res,
                                   f"inline policy '{pn}' allows Action '*'",
                                   lambda pn=pn: iam.delete_role_policy(RoleName=name, PolicyName=pn)))
                break
    for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
        if p["PolicyName"] == "AdministratorAccess":
            out.append(finding("IAM-ADMIN-ATTACHED", "HIGH", res, "AdministratorAccess is attached",
                               lambda arn=p["PolicyArn"]: iam.detach_role_policy(RoleName=name, PolicyArn=arn)))

    trust = iam.get_role(RoleName=name)["Role"]["AssumeRolePolicyDocument"]
    if isinstance(trust, str):
        trust = json.loads(unquote(trust))
    if any(is_public_statement(s) for s in as_list(trust.get("Statement"))):
        def fix_trust():
            raise RuntimeError("restrict the trust policy Principal by hand")
        out.append(finding("IAM-TRUST-WILDCARD", "HIGH", res,
                           "trust policy lets any principal assume this role", fix_trust))
    return out


# ---------------------------------------------------------------- run
def scan(prefix, kms_key):
    s3, iam = client("s3"), client("iam")
    found = []
    for b in s3.list_buckets().get("Buckets", []):
        if b["Name"].startswith(prefix):
            found += scan_bucket(s3, b["Name"], kms_key)
    for page in iam.get_paginator("list_roles").paginate():
        for r in page["Roles"]:
            if r["RoleName"].startswith(prefix):
                found += scan_role(iam, r["RoleName"])
    return found


def show(title, items):
    print(f"\n{title}: {len(items)} finding(s)")
    for f in items:
        print(f"  [{f['severity']:<6}] {f['id']:<26} {f['resource']:<28} {f['detail']}")


def public(items):
    return [{k: v for k, v in f.items() if k != "fix"} for f in items]


def notify(items, topic_arn, log_group):
    if log_group:
        logs = client("logs")
        stream = "scan-" + time.strftime("%Y%m%d-%H%M%S")
        call_or_none(logs.create_log_group, "ResourceAlreadyExistsException", logGroupName=log_group)
        logs.create_log_stream(logGroupName=log_group, logStreamName=stream)
        now = int(time.time() * 1000)
        events = [{"timestamp": now, "message":
                   f"SECFINDING_{f['severity']} id={f['id']} resource={f['resource']} detail={f['detail']}"}
                  for f in items] or [{"timestamp": now, "message": "SCAN_CLEAN no findings"}]
        logs.put_log_events(logGroupName=log_group, logStreamName=stream, logEvents=events)
    if topic_arn and items:
        high = sum(1 for f in items if f["severity"] == "HIGH")
        body = f"{len(items)} finding(s), {high} HIGH:\n" + "\n".join(
            f"- [{f['severity']}] {f['id']} {f['resource']}: {f['detail']}" for f in items)
        client("sns").publish(TopicArn=topic_arn, Subject="Security scan findings", Message=body)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--prefix", default="sec-lab", help="only scan buckets/roles whose name starts with this")
    ap.add_argument("--fix", action="store_true", help="apply remediation, then re-scan")
    ap.add_argument("--kms-key-id", help="KMS key id/alias used by the encryption fix (the fix fails without it)")
    ap.add_argument("--report", help="write JSON report to this path")
    ap.add_argument("--sns-topic-arn", help="publish a summary here when findings exist")
    ap.add_argument("--log-group", help="write one log line per finding here (for metric filters)")
    a = ap.parse_args()

    if not a.prefix:
        sys.exit("--prefix must not be empty (it protects other resources on the emulator)")

    before = scan(a.prefix, a.kms_key_id)
    show("BEFORE", before)
    after = before
    if a.fix and before:
        print("\nApplying fixes...")
        for f in before:
            try:
                f["fix"]()
                print(f"  fixed   {f['id']} {f['resource']}")
            except (ClientError, RuntimeError) as e:
                print(f"  FAILED  {f['id']} {f['resource']}: {e}")
        after = scan(a.prefix, a.kms_key_id)
        show("AFTER", after)

    if a.report:
        with open(a.report, "w", encoding="utf-8") as fh:
            json.dump({"prefix": a.prefix, "before": public(before), "after": public(after)}, fh, indent=2)
        print(f"\nReport: {a.report}")
    if a.sns_topic_arn or a.log_group:
        notify(after if a.fix else before, a.sns_topic_arn, a.log_group)
    sys.exit(1 if after else 0)


if __name__ == "__main__":
    main()
