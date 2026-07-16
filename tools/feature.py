import os
import sys
import socket
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

import requests

# Configure logging for production use
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class SecurityTool:
    """
    AWS Security Scanning Tool.

    Performs a series of checks against AWS resources and environments
    to identify common security misconfigurations and exposures.

    Attributes:
        target_buckets (List[str]): List of S3 bucket names to check.
        findings (List[Dict]): Accumulated scan findings.
        scan_start_time (datetime): Timestamp when the scan began.
        scan_end_time (datetime): Timestamp when the scan completed.
    """

    def __init__(self, target_buckets: Optional[List[str]] = None) -> None:
        """
        Initialize the security scanner.

        Args:
            target_buckets: Optional list of bucket names to include in the scan.
                            If None, an empty list is used.
        """
        self.target_buckets: List[str] = target_buckets if target_buckets else []
        self.findings: List[Dict[str, Any]] = []
        self.scan_start_time: Optional[datetime] = None
        self.scan_end_time: Optional[datetime] = None
        logger.info("SecurityTool initialized with target_buckets=%s", self.target_buckets)

    # ------------------------------------------------------------------
    # Main scanning orchestration
    # ------------------------------------------------------------------
    def scan(self) -> None:
        """
        Execute all security checks.

        This method runs the configured checks and populates the
        `findings` list with results.
        """
        self.scan_start_time = datetime.utcnow()
        logger.info("Scan started at %s", self.scan_start_time)

        try:
            self._check_ec2_metadata()
            self._check_env_secrets()
            self._check_open_ports()
            self._check_s3_buckets()
        except Exception as exc:
            logger.exception("Critical error during scan: %s", exc)
            self.findings.append({
                "severity": "HIGH",
                "check": "scan_critical_error",
                "detail": f"Unhandled exception: {exc}",
                "timestamp": self.scan_start_time.isoformat(),
            })

        self.scan_end_time = datetime.utcnow()
        logger.info("Scan completed at %s", self.scan_end_time)

    # ------------------------------------------------------------------
    # Individual security checks
    # ------------------------------------------------------------------
    def _check_ec2_metadata(self) -> None:
        """
        Check if the tool is running on an AWS EC2 instance by
        attempting to access the instance metadata service.

        Adds a finding if the metadata is accessible (potential
        security risk if the tool is not intended to run in EC2).
        """
        logger.info("Checking EC2 metadata accessibility...")
        try:
            # IMDSv1 (less secure) test
            resp = requests.get(
                "http://169.254.169.254/latest/meta-data/",
                timeout=2,
                headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            )
            if resp.status_code == 200:
                self.findings.append({
                    "severity": "MEDIUM",
                    "check": "ec2_metadata_accessible",
                    "detail": "EC2 metadata service is reachable. "
                              "Tool is likely running on an EC2 instance.",
                    "timestamp": datetime.utcnow().isoformat(),
                })
                logger.info("EC2 metadata accessible – running in AWS environment.")
            else:
                logger.info("EC2 metadata returned status %s", resp.status_code)
        except requests.ConnectionError:
            logger.info("EC2 metadata not reachable – not in AWS EC2.")
        except Exception as exc:
            logger.warning("Failed to check EC2 metadata: %s", exc)

    def _check_env_secrets(self) -> None:
        """
        Inspect environment variables for commonly named AWS secret keys.
        This is a basic check for accidental exposure of credentials.
        """
        logger.info("Checking environment variables for exposed secrets...")
        sensitive_env_keys = [
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_SECRET_KEY",
            "SECRET_KEY",
            "PASSWORD",
            "DB_PASSWORD",
            "API_KEY",
        ]
        for key in sensitive_env_keys:
            value = os.environ.get(key)
            if value and not self._is_placeholder(value):
                self.findings.append({
                    "severity": "HIGH",
                    "check": "exposed_env_secret",
                    "detail": f"Environment variable '{key}' appears to contain a "
                              f"real secret value (first 4 chars: {value[:4]}...)",
                    "timestamp": datetime.utcnow().isoformat(),
                })
                logger.info("Potential secret exposed in env: %s", key)

    @staticmethod
    def _is_placeholder(value: str) -> bool:
        """
        Determine if a string is a placeholder (e.g., "your-secret").

        Args:
            value: The string to evaluate.

        Returns:
            True if the value looks like a placeholder, False otherwise.
        """
        placeholders = [
            "your-", "changeme", "placeholder", "example", "test",
            "password", "secret", "xxxx", "****",
        ]
        lower_val = value.lower().strip()
        return any(ph in lower_val for ph in placeholders)

    def _check_open_ports(self, host: str = "127.0.0.1", port_list: Optional[List[int]] = None) -> None:
        """
        Check for commonly open ports on the specified host.

        This can indicate running services that may be misconfigured.

        Args:
            host: Hostname or IP address to scan. Defaults to localhost.
            port_list: List of ports to check. Defaults to common AWS
                       related ports (22, 3306, 5432, 6379, 27017, etc.)
        """
        if port_list is None:
            port_list = [22, 80, 443, 3306, 5432, 6379, 27017, 8080, 8443]
        logger.info("Checking open ports on %s...", host)
        for port in port_list:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    self.findings.append({
                        "severity": "LOW",
                        "check": f"open_port_{port}",
                        "detail": f"Port {port} is open on {host}.",
                        "timestamp": datetime.utcnow().isoformat(),
                    })
                    logger.info("Open port found: %s:%d", host, port)
            except socket.error as exc:
                logger.debug("Could not check port %d: %s", port, exc)

    def _check_s3_buckets(self) -> None:
        """
        Check whether specified S3 buckets are publicly accessible via HTTP.

        This is a basic check that tries to read the bucket listing over
        the internet. It does not require AWS credentials.
        """
        logger.info("Checking S3 bucket public accessibility...")
        for bucket_name in self.target_buckets:
            if not bucket_name:
                continue
            urls = [
                f"https://{bucket_name}.s3.amazonaws.com",
                f"http://{bucket_name}.s3.amazonaws.com",
            ]
            for url in urls:
                try:
                    resp = requests.get(url, timeout=5)
                    if resp.status_code in (200, 403):
                        # 403 means the bucket exists but access denied – still a finding
                        detail = (
                            f"Bucket '{bucket_name}' responded with HTTP {resp.status_code} "
                            f"at {url}. Bucket exists and is potentially reachable."
                        )
                        self.findings.append({
                            "severity": "MEDIUM" if resp.status_code == 200 else "LOW",
                            "check": f"s3_bucket_accessible_{bucket_name}",
                            "detail": detail,
                            "timestamp": datetime.utcnow().isoformat(),
                        })
                        logger.info("S3 bucket '%s' reachable at %s", bucket_name, url)
                    else:
                        logger.info("S3 bucket '%s' not found at %s", bucket_name, url)
                except requests.RequestException as exc:
                    logger.debug("Could not check bucket '%s': %s", bucket_name, exc)

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------
    def generate_report(self, output_format: str = "json") -> str:
        """
        Generate a report of all findings.

        Args:
            output_format: The desired output format. Currently only 'json'
                           is supported.

        Returns:
            A string containing the report in the specified format.
        """
        logger.info("Generating report (format=%s)...", output_format)
        report_data: Dict[str, Any] = {
            "tool": "SecurityTool",
            "scan_start": self.scan_start_time.isoformat() if self.scan_start_time else None,
            "scan_end": self.scan_end_time.isoformat() if self.scan_end_time else None,
            "target_buckets": self.target_buckets,
            "total_findings": len(self.findings),
            "findings": self.findings,
        }

        if output_format == "json":
            return json.dumps(report_data, indent=4)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")

    def print_report(self, output_format: str = "json") -> None:
        """
        Convenience method to print the report to stdout.

        Args:
            output_format: Format for the report (default 'json').
        """
        print(self.generate_report(output_format))


def main() -> None:
    """
    Entry point for command-line usage.

    Reads target bucket names from command-line arguments (if provided)
    and runs the security scan.
    """
    bucket_names = sys.argv[1:] if len(sys.argv) > 1 else None
    scanner = SecurityTool(target_buckets=bucket_names)
    scanner.scan()
    scanner.print_report()


if __name__ == "__main__":
    main()