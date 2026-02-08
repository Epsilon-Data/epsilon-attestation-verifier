"""
Command-line interface for attestation verification.
"""

import argparse
import json
import logging
import sys
from pathlib import Path

from .verifier import verify_attestation
from .pcr_registry import get_published_pcrs, list_known_versions


def setup_logging(verbose: bool):
    """Configure logging based on verbosity."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format='%(levelname)s: %(message)s'
    )


def cmd_verify(args):
    """Verify an attestation document."""
    # Load attestation document
    attestation_path = Path(args.attestation)
    if not attestation_path.exists():
        print(f"Error: Attestation file not found: {attestation_path}", file=sys.stderr)
        return 1

    attestation_data = attestation_path.read_text().strip()

    # Check if it's JSON (from Epsilon job response)
    try:
        json_data = json.loads(attestation_data)
        # Extract attestation document from nested structure
        if 'attestation' in json_data:
            if isinstance(json_data['attestation'], dict):
                if 'attestation' in json_data['attestation']:
                    if 'attestation_document' in json_data['attestation']['attestation']:
                        attestation_data = json_data['attestation']['attestation']['attestation_document']
                elif 'attestation_document' in json_data['attestation']:
                    attestation_data = json_data['attestation']['attestation_document']
    except json.JSONDecodeError:
        # Assume it's raw base64 attestation
        pass

    # Load expected output
    expected_output = None
    if args.output:
        output_path = Path(args.output)
        if output_path.exists():
            expected_output = output_path.read_text()
        else:
            expected_output = args.output

    # Get PCR values
    expected_pcr0 = args.pcr0
    expected_pcr1 = args.pcr1
    expected_pcr2 = args.pcr2

    # Load from version if specified
    if args.version:
        pcrs = get_published_pcrs(args.version)
        if pcrs:
            expected_pcr0 = expected_pcr0 or pcrs.pcr0
            expected_pcr1 = expected_pcr1 or pcrs.pcr1
            expected_pcr2 = expected_pcr2 or pcrs.pcr2
        else:
            print(f"Warning: Unknown version {args.version}", file=sys.stderr)

    # Verify
    result = verify_attestation(
        attestation_doc=attestation_data,
        expected_output=expected_output,
        expected_pcr0=expected_pcr0,
        expected_pcr1=expected_pcr1,
        expected_pcr2=expected_pcr2,
        aws_root_cert_path=args.aws_root_cert,
        skip_certificate_verification=args.skip_cert_verification,
    )

    # Output results
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_result(result)

    return 0 if result.valid else 1


def _print_result(result):
    """Print verification result in human-readable format."""
    if result.valid:
        print("\n✓ ATTESTATION VERIFIED")
        print("=" * 50)
    else:
        print("\n✗ VERIFICATION FAILED")
        print("=" * 50)
        if result.error:
            print(f"Error: {result.error}")
        print()

    print(f"AWS Signature:        {'✓' if result.aws_signature_valid else '✗'}")
    print(f"Certificate Chain:    {'✓' if result.certificate_chain_valid else '✗'}")
    print(f"PCR Values:           {'✓' if result.pcr_verified else '✗'}")
    print(f"Output Hash:          {'✓' if result.output_verified else '✗'}")

    print()
    print("PCR Values:")
    print(f"  PCR0: {result.pcr0 or 'N/A'}")
    print(f"  PCR1: {result.pcr1 or 'N/A'}")
    print(f"  PCR2: {result.pcr2 or 'N/A'}")

    if result.timestamp:
        print(f"\nTimestamp: {result.timestamp}")
    if result.module_id:
        print(f"Module ID: {result.module_id}")

    if result.output_hash:
        print(f"\nOutput Hash: {result.output_hash}")
    if result.expected_output_hash:
        print(f"Expected:    {result.expected_output_hash}")

    if result.user_data:
        print(f"\nUser Data:")
        for key, value in result.user_data.items():
            if key != 'output_hash':
                print(f"  {key}: {value}")

    print()


def cmd_list_versions(args):
    """List known enclave versions."""
    versions = list_known_versions()
    if not versions:
        print("No known versions in built-in registry.")
        print("Use --fetch-latest to get versions from GitHub.")
        return 0

    print("Known Epsilon Enclave Versions:")
    for version in sorted(versions):
        pcrs = get_published_pcrs(version)
        if pcrs:
            print(f"\n  {version}")
            print(f"    PCR0: {pcrs.pcr0[:32]}...")
            if pcrs.release_date:
                print(f"    Released: {pcrs.release_date}")

    return 0


def cmd_extract(args):
    """Extract information from attestation without verification."""
    attestation_path = Path(args.attestation)
    if not attestation_path.exists():
        print(f"Error: Attestation file not found: {attestation_path}", file=sys.stderr)
        return 1

    attestation_data = attestation_path.read_text().strip()

    # Parse JSON if needed
    try:
        json_data = json.loads(attestation_data)
        if 'attestation' in json_data:
            if isinstance(json_data['attestation'], dict):
                if 'attestation' in json_data['attestation']:
                    if 'attestation_document' in json_data['attestation']['attestation']:
                        attestation_data = json_data['attestation']['attestation']['attestation_document']
    except json.JSONDecodeError:
        pass

    # Verify with skip options to just extract data
    result = verify_attestation(
        attestation_doc=attestation_data,
        skip_certificate_verification=True,
    )

    output = {
        'pcr0': result.pcr0,
        'pcr1': result.pcr1,
        'pcr2': result.pcr2,
        'timestamp': result.timestamp.isoformat() if result.timestamp else None,
        'module_id': result.module_id,
        'user_data': result.user_data,
        'output_hash': result.output_hash,
    }

    print(json.dumps(output, indent=2))
    return 0


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Verify AWS Nitro Enclave attestation documents from Epsilon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Verify attestation with expected output
  epsilon-verify verify attestation.json --output output.txt

  # Verify with specific PCR0
  epsilon-verify verify attestation.json --pcr0 abc123...

  # Extract PCR values without verification
  epsilon-verify extract attestation.json

  # Output as JSON
  epsilon-verify verify attestation.json --json
        """
    )
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # verify command
    verify_parser = subparsers.add_parser('verify', help='Verify attestation document')
    verify_parser.add_argument('attestation', help='Attestation document (JSON or base64)')
    verify_parser.add_argument('--output', '-o', help='Expected output file or string')
    verify_parser.add_argument('--pcr0', help='Expected PCR0 value')
    verify_parser.add_argument('--pcr1', help='Expected PCR1 value')
    verify_parser.add_argument('--pcr2', help='Expected PCR2 value')
    verify_parser.add_argument('--version', help='Epsilon version (loads expected PCRs)')
    verify_parser.add_argument('--aws-root-cert', help='Path to AWS root certificate')
    verify_parser.add_argument('--skip-cert-verification', action='store_true',
                               help='Skip certificate chain verification (testing only)')
    verify_parser.add_argument('--json', action='store_true', help='Output as JSON')

    # extract command
    extract_parser = subparsers.add_parser('extract', help='Extract data from attestation')
    extract_parser.add_argument('attestation', help='Attestation document (JSON or base64)')

    # list-versions command
    list_parser = subparsers.add_parser('list-versions', help='List known enclave versions')
    list_parser.add_argument('--fetch-latest', action='store_true',
                             help='Fetch latest from GitHub')

    args = parser.parse_args()

    setup_logging(args.verbose)

    if args.command == 'verify':
        return cmd_verify(args)
    elif args.command == 'extract':
        return cmd_extract(args)
    elif args.command == 'list-versions':
        return cmd_list_versions(args)
    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())
