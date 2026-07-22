"""
CI/CD Scanner entrypoint for automated pipeline security gating.
Runs CodeMender security audit on target repo and exits with non-zero status if unresolved critical vulnerabilities exist.
"""

import argparse
import json
import sys
from codemender_agent.config import SeverityLevel, VulnerabilityStatus
from codemender_agent.tools.cli_wrapper import CodeMenderCLIWrapper


def main():
    parser = argparse.ArgumentParser(description="CodeMender CI/CD Security Gate Scanner")
    parser.add_argument("--repo-path", default=".", help="Path to local target repository")
    parser.add_argument(
        "--severity-threshold",
        default="HIGH",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Minimum severity threshold to trigger CI build failure",
    )
    parser.add_argument("--auto-fix", action="store_true", default=True, help="Automatically attempt patch generation & verification")
    parser.add_argument("--output-report", default="codemender-report.md", help="Path to write output security report")

    args = parser.parse_args()
    print(f"=== Starting CodeMender Security Gate for: {args.repo_path} ===")

    cli = CodeMenderCLIWrapper()
    env_info = cli.check_environment()
    print(f"[*] CodeMender Environment: {env_info.get('version')} ({env_info.get('mode')})")

    print("[*] Running SAST & SCA Vulnerability Scans...")
    sast_vulns = cli.scan_sast(args.repo_path)
    sca_vulns = cli.scan_sca(args.repo_path)
    all_vulns = sast_vulns + sca_vulns

    print(f"[*] Total Discovered Vulnerabilities: {len(all_vulns)}")

    unresolved_high = 0
    fixed_count = 0

    if args.auto_fix:
        print("[*] Entering Iterative Repair & Verification Loop...")
        for v in all_vulns:
            vid = v.get("vuln_id")
            severity = v.get("severity", "LOW")
            print(f"  -> Processing {vid} ({severity}): {v.get('title')}")

            # Generate fix
            fix_res = cli.generate_fix(args.repo_path, vid)
            v["patch_diff"] = fix_res.get("patch_diff")

            # Verify fix
            ver_res = cli.verify_fix(args.repo_path, vid)
            if ver_res.get("verified"):
                v["status"] = VulnerabilityStatus.VERIFIED_FIXED.value
                fixed_count += 1
                print(f"     [✓] Verified Fixed!")
            else:
                v["status"] = VulnerabilityStatus.FAILED.value
                print(f"     [✗] Fix Verification Failed")

    # Evaluate residual risk against severity threshold
    severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    threshold_val = severity_order.get(args.severity_threshold, 3)

    for v in all_vulns:
        if v.get("status") != VulnerabilityStatus.VERIFIED_FIXED.value:
            v_sev_val = severity_order.get(v.get("severity"), 1)
            if v_sev_val >= threshold_val:
                unresolved_high += 1

    # Export report
    report_md = cli.export_report(args.repo_path, output_format="markdown", vulnerabilities=all_vulns)
    with open(args.output_report, "w", encoding="utf-8") as f:
        f.write(report_md)
    print(f"[*] Security Audit Report written to: {args.output_report}")

    print("\n=== Summary ===")
    print(f"Total Discovered: {len(all_vulns)}")
    print(f"Remediated & Verified: {fixed_count}")
    print(f"Unresolved Gating Vulnerabilities: {unresolved_high}")

    if unresolved_high > 0:
        print(f"[!] CI SECURITY GATE FAILED: {unresolved_high} unhandled vulnerability(s) at or above {args.severity_threshold} threshold.")
        sys.exit(1)
    else:
        print("[✓] CI SECURITY GATE PASSED: All gating vulnerabilities remediated or within threshold.")
        sys.exit(0)


if __name__ == "__main__":
    main()
