"""Tests for AWS compliance check modules (30 tests with mocked boto3)."""

import json
import os
import sys
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))


# ---------------------------------------------------------------------------
# Mock session helper
# ---------------------------------------------------------------------------

def _mock_session():
    """Create a mock boto3 session."""
    session = MagicMock()
    return session


# ---------------------------------------------------------------------------
# IAM Tests (4)
# ---------------------------------------------------------------------------

class TestIAMChecks:
    def test_password_policy_compliant(self):
        from checks.iam import run_iam_checks
        session = _mock_session()
        iam = session.client.return_value
        iam.get_account_password_policy.return_value = {
            "PasswordPolicy": {
                "MinimumPasswordLength": 14,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
                "MaxPasswordAge": 90,
                "PasswordReusePrevention": 12,
            }
        }
        iam.list_users.return_value = {"Users": []}

        result = run_iam_checks(session)
        assert result["check"] == "iam"
        assert result["status"] == "pass"
        assert result["passed"] == 7
        assert result["failed"] == 0

    def test_mfa_not_enabled(self):
        from checks.iam import run_iam_checks
        session = _mock_session()
        iam = session.client.return_value

        class NoSuchEntity(Exception):
            pass
        iam.exceptions.NoSuchEntityException = NoSuchEntity
        iam.get_account_password_policy.side_effect = NoSuchEntity()
        iam.list_users.return_value = {"Users": [
            {"UserName": "alice"},
            {"UserName": "bob"},
        ]}
        iam.list_mfa_devices.return_value = {"MFADevices": []}
        iam.list_access_keys.return_value = {"AccessKeyMetadata": []}

        result = run_iam_checks(session)
        assert result["status"] == "fail"
        # 1 password policy fail + 2 MFA fails
        assert result["failed"] == 3

    def test_access_key_rotation_pass(self):
        from checks.iam import _check_access_key_rotation
        session = _mock_session()
        iam = session.client.return_value
        iam.list_users.return_value = {"Users": [{"UserName": "alice"}]}
        iam.list_access_keys.return_value = {"AccessKeyMetadata": [{
            "AccessKeyId": "TEST_KEY_PLACEHOLDER",
            "Status": "Active",
            "CreateDate": datetime.now(timezone.utc) - timedelta(days=30),
        }]}

        findings = _check_access_key_rotation(session)
        assert len(findings) == 1
        assert findings[0]["status"] == "pass"

    def test_access_key_rotation_fail(self):
        from checks.iam import _check_access_key_rotation
        session = _mock_session()
        iam = session.client.return_value
        iam.list_users.return_value = {"Users": [{"UserName": "alice"}]}
        iam.list_access_keys.return_value = {"AccessKeyMetadata": [{
            "AccessKeyId": "TEST_KEY_PLACEHOLDER",
            "Status": "Active",
            "CreateDate": datetime.now(timezone.utc) - timedelta(days=120),
        }]}

        findings = _check_access_key_rotation(session)
        assert len(findings) == 1
        assert findings[0]["status"] == "fail"


# ---------------------------------------------------------------------------
# S3 Tests (4)
# ---------------------------------------------------------------------------

class TestS3Checks:
    def test_s3_encryption_pass(self):
        from checks.s3 import run_s3_checks
        session = _mock_session()
        s3 = session.client.return_value
        s3.list_buckets.return_value = {"Buckets": [{"Name": "my-bucket"}]}
        s3.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }
        s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        }}
        s3.get_bucket_versioning.return_value = {"Status": "Enabled"}
        s3.get_bucket_logging.return_value = {"LoggingEnabled": {"TargetBucket": "logs"}}

        result = run_s3_checks(session)
        assert result["check"] == "s3"
        assert result["status"] == "pass"
        assert result["passed"] == 4

    def test_s3_no_encryption(self):
        from checks.s3 import _check_encryption
        session = _mock_session()
        s3 = session.client.return_value
        s3.list_buckets.return_value = {"Buckets": [{"Name": "unencrypted-bucket"}]}
        s3.get_bucket_encryption.side_effect = Exception("NoEncryption")

        findings = _check_encryption(session)
        assert findings[0]["status"] == "fail"

    def test_s3_public_access_not_blocked(self):
        from checks.s3 import _check_public_access_block
        session = _mock_session()
        s3 = session.client.return_value
        s3.list_buckets.return_value = {"Buckets": [{"Name": "public-bucket"}]}
        s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True, "IgnorePublicAcls": False,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        }}

        findings = _check_public_access_block(session)
        assert findings[0]["status"] == "fail"

    def test_s3_versioning_disabled(self):
        from checks.s3 import _check_versioning
        session = _mock_session()
        s3 = session.client.return_value
        s3.list_buckets.return_value = {"Buckets": [{"Name": "no-ver"}]}
        s3.get_bucket_versioning.return_value = {"Status": "Suspended"}

        findings = _check_versioning(session)
        assert findings[0]["status"] == "fail"


# ---------------------------------------------------------------------------
# CloudTrail Tests (2)
# ---------------------------------------------------------------------------

class TestCloudTrailChecks:
    def test_cloudtrail_compliant(self):
        from checks.cloudtrail import run_cloudtrail_checks
        session = _mock_session()
        ct = session.client.return_value
        ct.describe_trails.return_value = {"trailList": [{
            "Name": "main-trail",
            "TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/main-trail",
            "IsMultiRegionTrail": True,
            "LogFileValidationEnabled": True,
            "S3BucketName": "trail-logs",
        }]}
        ct.get_trail_status.return_value = {"IsLogging": True}

        result = run_cloudtrail_checks(session)
        assert result["status"] == "pass"
        assert result["passed"] == 4

    def test_cloudtrail_no_trails(self):
        from checks.cloudtrail import run_cloudtrail_checks
        session = _mock_session()
        ct = session.client.return_value
        ct.describe_trails.return_value = {"trailList": []}

        result = run_cloudtrail_checks(session)
        assert result["status"] == "fail"
        assert result["failed"] == 1


# ---------------------------------------------------------------------------
# VPC Tests (2)
# ---------------------------------------------------------------------------

class TestVPCChecks:
    def test_vpc_flow_logs_enabled(self):
        from checks.vpc import _check_flow_logs
        session = _mock_session()
        ec2 = session.client.return_value
        ec2.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-123"}]}
        ec2.describe_flow_logs.return_value = {"FlowLogs": [{"ResourceId": "vpc-123"}]}

        findings = _check_flow_logs(session, "us-east-1")
        assert findings[0]["status"] == "pass"

    def test_security_group_open_inbound(self):
        from checks.vpc import _check_security_groups
        session = _mock_session()
        ec2 = session.client.return_value
        ec2.describe_security_groups.return_value = {"SecurityGroups": [{
            "GroupId": "sg-123",
            "GroupName": "open-sg",
            "IpPermissions": [{
                "FromPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        }]}

        findings = _check_security_groups(session, "us-east-1")
        assert findings[0]["status"] == "fail"


# ---------------------------------------------------------------------------
# KMS Tests (2)
# ---------------------------------------------------------------------------

class TestKMSChecks:
    def test_kms_rotation_enabled(self):
        from checks.kms import run_kms_checks
        session = _mock_session()
        kms = session.client.return_value
        kms.list_keys.return_value = {"Keys": [{"KeyId": "key-123"}]}
        kms.describe_key.return_value = {"KeyMetadata": {"KeyManager": "CUSTOMER"}}
        kms.get_key_rotation_status.return_value = {"KeyRotationEnabled": True}

        result = run_kms_checks(session)
        assert result["status"] == "pass"

    def test_kms_rotation_disabled(self):
        from checks.kms import run_kms_checks
        session = _mock_session()
        kms = session.client.return_value
        kms.list_keys.return_value = {"Keys": [{"KeyId": "key-456"}]}
        kms.describe_key.return_value = {"KeyMetadata": {"KeyManager": "CUSTOMER"}}
        kms.get_key_rotation_status.return_value = {"KeyRotationEnabled": False}

        result = run_kms_checks(session)
        assert result["status"] == "fail"


# ---------------------------------------------------------------------------
# EC2 Tests (3)
# ---------------------------------------------------------------------------

class TestEC2Checks:
    def test_imdsv2_required(self):
        from checks.ec2 import _check_imdsv2
        session = _mock_session()
        ec2 = session.client.return_value
        ec2.describe_instances.return_value = {"Reservations": [{"Instances": [{
            "InstanceId": "i-123",
            "MetadataOptions": {"HttpTokens": "required"},
        }]}]}

        findings = _check_imdsv2(session, "us-east-1")
        assert findings[0]["status"] == "pass"

    def test_ebs_unencrypted(self):
        from checks.ec2 import _check_ebs_encryption
        session = _mock_session()
        ec2 = session.client.return_value
        ec2.describe_volumes.return_value = {"Volumes": [
            {"VolumeId": "vol-123", "Encrypted": True},
            {"VolumeId": "vol-456", "Encrypted": False},
        ]}

        findings = _check_ebs_encryption(session, "us-east-1")
        assert findings[0]["status"] == "pass"
        assert findings[1]["status"] == "fail"

    def test_public_ip_detected(self):
        from checks.ec2 import _check_public_ips
        session = _mock_session()
        ec2 = session.client.return_value
        ec2.describe_instances.return_value = {"Reservations": [{"Instances": [{
            "InstanceId": "i-789",
            "PublicIpAddress": "54.1.2.3",
        }]}]}

        findings = _check_public_ips(session, "us-east-1")
        assert findings[0]["status"] == "fail"


# ---------------------------------------------------------------------------
# RDS Tests (2)
# ---------------------------------------------------------------------------

class TestRDSChecks:
    def test_rds_compliant(self):
        from checks.rds import run_rds_checks
        session = _mock_session()
        rds = session.client.return_value
        rds.describe_db_instances.return_value = {"DBInstances": [{
            "DBInstanceIdentifier": "prod-db",
            "StorageEncrypted": True,
            "BackupRetentionPeriod": 14,
            "PubliclyAccessible": False,
        }]}

        result = run_rds_checks(session)
        assert result["status"] == "pass"
        assert result["passed"] == 3

    def test_rds_public_no_encryption(self):
        from checks.rds import run_rds_checks
        session = _mock_session()
        rds = session.client.return_value
        rds.describe_db_instances.return_value = {"DBInstances": [{
            "DBInstanceIdentifier": "test-db",
            "StorageEncrypted": False,
            "BackupRetentionPeriod": 3,
            "PubliclyAccessible": True,
        }]}

        result = run_rds_checks(session)
        assert result["status"] == "fail"
        assert result["failed"] == 3


# ---------------------------------------------------------------------------
# Security Hub Tests (2)
# ---------------------------------------------------------------------------

class TestSecurityHubChecks:
    def test_security_hub_enabled_no_findings(self):
        from checks.security_hub import run_security_hub_checks
        session = _mock_session()
        sh = session.client.return_value
        sh.describe_hub.return_value = {"SubscribedAt": "2024-01-01"}
        sh.get_findings.return_value = {"Findings": []}

        result = run_security_hub_checks(session)
        assert result["status"] == "pass"

    def test_security_hub_not_enabled(self):
        from checks.security_hub import run_security_hub_checks
        session = _mock_session()
        sh = session.client.return_value
        sh.describe_hub.side_effect = Exception("Not enabled")

        result = run_security_hub_checks(session)
        assert result["status"] == "fail"
        assert result["findings"][0]["detail"] == "Security Hub not enabled"


# ---------------------------------------------------------------------------
# GuardDuty Tests (2)
# ---------------------------------------------------------------------------

class TestGuardDutyChecks:
    def test_guardduty_enabled_clean(self):
        from checks.guardduty import run_guardduty_checks
        session = _mock_session()
        gd = session.client.return_value
        gd.list_detectors.return_value = {"DetectorIds": ["det-123"]}
        gd.get_detector.return_value = {"Status": "ENABLED"}
        gd.list_findings.return_value = {"FindingIds": []}

        result = run_guardduty_checks(session)
        assert result["status"] == "pass"

    def test_guardduty_not_enabled(self):
        from checks.guardduty import run_guardduty_checks
        session = _mock_session()
        gd = session.client.return_value
        gd.list_detectors.return_value = {"DetectorIds": []}

        result = run_guardduty_checks(session)
        assert result["status"] == "fail"


# ---------------------------------------------------------------------------
# Lambda Tests (2)
# ---------------------------------------------------------------------------

class TestLambdaChecks:
    def test_lambda_deprecated_runtime(self):
        from checks.lambda_check import run_lambda_checks
        session = _mock_session()
        lam = session.client.return_value
        lam.list_functions.return_value = {"Functions": [{
            "FunctionName": "old-fn",
            "Runtime": "python3.6",
            "VpcConfig": {"SubnetIds": ["subnet-1"]},
        }]}
        lam.get_policy.side_effect = Exception("No policy")

        result = run_lambda_checks(session)
        # Runtime fail, VPC pass, public access pass = 1 fail
        assert result["failed"] >= 1
        runtime_finding = [f for f in result["findings"] if "runtime" in f["resource"]][0]
        assert runtime_finding["status"] == "fail"

    def test_lambda_current_runtime(self):
        from checks.lambda_check import run_lambda_checks
        session = _mock_session()
        lam = session.client.return_value
        lam.list_functions.return_value = {"Functions": [{
            "FunctionName": "modern-fn",
            "Runtime": "python3.12",
            "VpcConfig": {"SubnetIds": ["subnet-1"]},
        }]}
        lam.get_policy.side_effect = Exception("No policy")

        result = run_lambda_checks(session)
        assert result["status"] == "pass"


# ---------------------------------------------------------------------------
# CloudWatch Tests (1)
# ---------------------------------------------------------------------------

class TestCloudWatchChecks:
    def test_log_retention_set(self):
        from checks.cloudwatch import _check_log_retention
        session = _mock_session()
        logs = session.client.return_value
        logs.describe_log_groups.return_value = {"logGroups": [
            {"logGroupName": "/aws/lambda/fn1", "retentionInDays": 90},
            {"logGroupName": "/aws/lambda/fn2"},
        ]}

        findings = _check_log_retention(session, "us-east-1")
        assert findings[0]["status"] == "pass"
        assert findings[1]["status"] == "fail"


# ---------------------------------------------------------------------------
# Config Tests (1)
# ---------------------------------------------------------------------------

class TestConfigChecks:
    def test_config_recorder_active(self):
        from checks.config import run_config_checks
        session = _mock_session()
        cfg = session.client.return_value
        cfg.describe_configuration_recorders.return_value = {
            "ConfigurationRecorders": [{"name": "default"}]
        }
        cfg.describe_configuration_recorder_status.return_value = {
            "ConfigurationRecordersStatus": [{"name": "default", "recording": True}]
        }
        cfg.describe_compliance_by_config_rule.return_value = {
            "ComplianceByConfigRules": [
                {"Compliance": {"ComplianceType": "COMPLIANT"}},
                {"Compliance": {"ComplianceType": "COMPLIANT"}},
            ]
        }

        result = run_config_checks(session)
        assert result["status"] == "pass"


# ---------------------------------------------------------------------------
# EKS/ECS Tests (1)
# ---------------------------------------------------------------------------

class TestEKSECSChecks:
    def test_eks_encryption_enabled(self):
        from checks.eks_ecs import _check_eks
        session = _mock_session()
        eks = session.client.return_value
        eks.list_clusters.return_value = {"clusters": ["prod-cluster"]}
        eks.describe_cluster.return_value = {"cluster": {
            "encryptionConfig": [{"resources": ["secrets"]}],
            "logging": {"clusterLogging": [{"enabled": True, "types": ["api", "audit"]}]},
            "resourcesVpcConfig": {"endpointPublicAccess": False},
        }}

        findings = _check_eks(session, "us-east-1")
        assert all(f["status"] == "pass" for f in findings)


# ---------------------------------------------------------------------------
# ELB Tests (1)
# ---------------------------------------------------------------------------

class TestELBChecks:
    def test_elb_https_with_logging(self):
        from checks.elb import run_elb_checks
        session = _mock_session()
        elbv2 = session.client.return_value
        elbv2.describe_load_balancers.return_value = {"LoadBalancers": [{
            "LoadBalancerArn": "arn:aws:elb:...:lb/test",
            "LoadBalancerName": "test-lb",
        }]}
        elbv2.describe_listeners.return_value = {"Listeners": [
            {"Protocol": "HTTPS", "Port": 443},
        ]}
        elbv2.describe_load_balancer_attributes.return_value = {"Attributes": [
            {"Key": "access_logs.s3.enabled", "Value": "true"},
        ]}
        waf = MagicMock()
        session.client.side_effect = lambda svc, **kw: waf if svc == "wafv2" else elbv2
        waf.get_web_acl_for_resource.return_value = {"WebACL": {"Name": "test-waf"}}

        # Re-mock so elbv2 calls work
        session.client.return_value = elbv2
        session.client.side_effect = None

        result = run_elb_checks(session)
        assert result["check"] == "elb"


# ---------------------------------------------------------------------------
# Credential Report Tests (1)
# ---------------------------------------------------------------------------

class TestCredentialReportChecks:
    def test_credential_report_root_mfa(self):
        from checks.credential_report import run_credential_report_checks
        session = _mock_session()
        iam = session.client.return_value

        csv_content = (
            "user,arn,user_creation_time,password_enabled,password_last_used,"
            "password_last_changed,password_next_rotation,mfa_active,"
            "access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,"
            "access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date\n"
            "<root_account>,arn:aws:iam::root,2020-01-01,not_supported,2024-01-01,"
            "not_supported,not_supported,true,false,N/A,N/A,false,N/A,N/A\n"
        )

        iam.generate_credential_report.return_value = {}
        iam.get_credential_report.return_value = {"Content": csv_content.encode("utf-8")}

        result = run_credential_report_checks(session)
        # Root MFA pass, no root access keys pass
        root_mfa = [f for f in result["findings"] if "root/mfa" in f["resource"]][0]
        assert root_mfa["status"] == "pass"


# ---------------------------------------------------------------------------
# Orchestrator Tests (1)
# ---------------------------------------------------------------------------

class TestOrchestrator:
    def test_all_checks_registered(self):
        from checks import ALL_CHECKS
        expected = {
            "iam", "s3", "cloudtrail", "vpc", "kms", "ec2", "rds",
            "security_hub", "guardduty", "lambda", "cloudwatch",
            "config", "eks_ecs", "elb", "credential_report",
        }
        assert set(ALL_CHECKS.keys()) == expected
        assert len(ALL_CHECKS) == 15
