import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

import requests


class SecurityTool:
    """
    A comprehensive security scanning tool for AWS resources.

    This tool analyzes provided AWS resource configurations for common security
    misconfigurations and generates a detailed report of findings.

    Attributes:
        aws_resources (dict): Dictionary containing AWS resource configurations.
        results (dict): Dictionary storing scan results.
    """

    def __init__(self, aws_resources: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize the SecurityTool.

        Args:
            aws_resources: Optional dictionary containing AWS resource configurations.
                Expected structure:
                {
                    "s3_buckets": [{"name": "example-bucket", "policy": {...}, "acl": {...}}],
                    "security_groups": [{"sg_name": "sg-xxx", "rules": [...]}],
                    "iam_users": [{"username": "user1", "mfa_enabled": False, ...}]
                }
        """
        self.aws_resources = aws_resources or {}
        self.results: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "scanner": "SecurityTool v1.0",
            "findings": []
        }
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter("[%(levelname)s] %(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def scan_all(self) -> None:
        """Run all available security checks in sequence."""
        self.logger.info("Starting comprehensive security scan...")
        self.scan_s3_buckets()
        self.scan_security_groups()
        self.scan_iam_users()
        self._check_logging()
        self.logger.info("Scan completed. Found {} findings.".format(
            len(self.results["findings"])
        ))

    def scan_s3_buckets(self) -> None:
        """Scan S3 bucket configurations for public access and insecure policies."""
        buckets = self.aws_resources.get("s3_buckets", [])
        if not buckets:
            self.logger.info("No S3 buckets to scan.")
            return

        for bucket in buckets:
            name = bucket.get("name", "unknown")
            policy = bucket.get("policy", {})
            acl = bucket.get("acl", {})

            # Check for public access in bucket policy
            if "Allow" in str(policy) and ("*" in str(policy) or "Principal" in str(policy)):
                self._add_finding(
                    "S3 Bucket Policy",
                    f"Bucket '{name}' has a potentially public policy.",
                    "HIGH"
                )

            # Check for public ACL
            if "public-read" in str(acl) or "public-read-write" in str(acl):
                self._add_finding(
                    "S3 Bucket ACL",
                    f"Bucket '{name}' has a public ACL.",
                    "CRITICAL"
                )

            # Check for missing server-side encryption
            encryption = bucket.get("encryption", None)
            if not encryption or encryption.get("rule") is None:
                self._add_finding(
                    "S3 Bucket Encryption",
                    f"Bucket '{name}' does not have default encryption enabled.",
                    "MEDIUM"
                )

    def scan_security_groups(self) -> None:
        """Scan EC2 security groups for overly permissive inbound rules."""
        sgs = self.aws_resources.get("security_groups", [])
        if not sgs:
            self.logger.info("No security groups to scan.")
            return

        for sg in sgs:
            sg_name = sg.get("sg_name", "unknown")
            rules = sg.get("rules", [])
            for rule in rules:
                if rule.get("direction") == "inbound":
                    cidr = rule.get("cidr", "")
                    port = rule.get("port", "all")
                    if cidr == "0.0.0.0/0":
                        if port in [22, 3389, 3306, 5432, 9200, 6379, 27017, "all"]:
                            self._add_finding(
                                "Security Group Inbound Rule",
                                f"Security group '{sg_name}' allows public access to "
                                f"port {port} from 0.0.0.0/0.",
                                "HIGH"
                            )
                    # Check for overly broad non-public ranges (e.g., /0 portion)
                    if cidr.startswith("10.") or cidr.startswith("172.") or cidr.startswith("192."):
                        # Private ranges are generally fine but still check
                        pass

    def scan_iam_users(self) -> None:
        """Scan IAM users for missing MFA, unused credentials, and risky policies."""
        users = self.aws_resources.get("iam_users", [])
        if not users:
            self.logger.info("No IAM users to scan.")
            return

        for user in users:
            username = user.get("username", "unknown")

            # MFA not enabled
            if not user.get("mfa_enabled", False):
                self._add_finding(
                    "IAM User MFA",
                    f"IAM user '{username}' does not have multi-factor authentication enabled.",
                    "HIGH"
                )

            # Check for access keys older than 90 days
            access_keys = user.get("access_keys", [])
            for key in access_keys:
                if key.get("active", False):
                    # In a real scenario, parse creation date; here simulate check
                    key_age_days = key.get("age_days", 0)
                    if key_age_days > 90:
                        self._add_finding(
                            "IAM User Access Key Age",
                            f"User '{username}' has an access key {key['id']} "
                            f"that is {key_age_days} days old (exceeds 90 day limit).",
                            "MEDIUM"
                        )

            # Check for excessive privileges (simulate by policy name)
            attached_policies = user.get("policies", [])
            for policy in attached_policies:
                if policy in ["AdministratorAccess", "PowerUserAccess"]:
                    self._add_finding(
                        "IAM User Policy",
                        f"User '{username}' has the overly permissive policy '{policy}'.",
                        "CRITICAL"
                    )

    def _check_logging(self) -> None:
        """Check if CloudTrail or other logging is enabled (placeholder)."""
        logging_enabled = self.aws_resources.get("logging", {}).get("cloudtrail", False)
        if not logging_enabled:
            self._add_finding(
                "Logging Configuration",
                "CloudTrail is not enabled for the account. Security logging is missing.",
                "HIGH"
            )

    def _add_finding(self, category: str, description: str, severity: str) -> None:
        """Internal method to add a finding to the results."""
        finding = {
            "category": category,
            "description": description,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        self.results["findings"].append(finding)
        self.logger.warning(f"{severity}: {description}")

    def generate_report(self, output_format: str = "json") -> Any:
        """
        Generate a report of all scan findings.

        Args:
            output_format: The desired report format. Currently supports "json" and "text".

        Returns:
            report: A formatted string or dictionary containing the findings.

        Raises:
            ValueError: If an unsupported format is specified.
        """
        if output_format == "json":
            return json.dumps(self.results, indent=2)
        elif output_format == "text":
            lines = [
                "=" * 60,
                " Security Scan Report",
                f" Timestamp: {self.results['timestamp']}",
                f" Scanner: {self.results['scanner']}",
                f" Total Findings: {len(self.results['findings'])}",
                "=" * 60,
            ]
            if not self.results["findings"]:
                lines.append("\n No issues found. Your resources appear secure.")
            else:
                for i, finding in enumerate(self.results["findings"], 1):
                    lines.append(f"\n Finding #{i}")
                    lines.append(f"   Category  : {finding['category']}")
                    lines.append(f"   Severity  : {finding['severity']}")
                    lines.append(f"   Description: {finding['description']}")
            lines.append("\n" + "=" * 60)
            return "\n".join(lines)
        else:
            raise ValueError(f"Unsupported report format: {output_format}")

    def fetch_resources_from_aws(self, access_key: str, secret_key: str