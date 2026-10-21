"""
Command-line interface for attestation verification.
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from .code_digest import compute_code_digest
from .verifier import verify_attestation
from .pcr_registry import get_published_pcrs, list_known_versions


def setup_logging(verbose: bool):
    """Configure logging based on verbosity."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format='%(levelname)s: %(message)s'
    )


def _load_output_files(files: Optional[List[str]], files_root: Optional[str]) -> List[Tuple[str, bytes]]:
    """
    Load output files as (name, bytes) pairs.

    Without files_root each file is named by its basename. With files_root each
    file is named by its path relative to that directory ("/" separated); when
    no files are listed, every file under files_root is loaded (symlinks and
    other non-regular entries are rejected, like the enclave does).
    Raises ValueError with a user-facing message.
    """
    if files_root is None:
        loaded = []
        for file_arg in files or []:
            file_path = Path(file_arg)
            if not file_path.is_file():
                raise ValueError(f"Output file not found: {file_path}")
            loaded.append((file_path.name, file_path.read_bytes()))
        return loaded

    root = Path(os.path.abspath(files_root))
    if not root.is_dir():
        raise ValueError(f"Files root is not a directory: {files_root}")

    if files:
        paths = [Path(os.path.abspath(file_arg)) for file_arg in files]
    else:
        paths = []
        for dirpath, dirnames, filenames in os.walk(root):
            for entry in sorted(dirnames + filenames):
                entry_path = Path(dirpath) / entry
                if entry_path.is_symlink() or not (entry_path.is_dir() or entry_path.is_file()):
                    raise ValueError(f"Not a regular file or directory: {entry_path}")
                if entry_path.is_file():
                    paths.append(entry_path)

    loaded = []
    for file_path in paths:
        if file_path.is_symlink() or not file_path.is_file():
            raise ValueError(f"Output file not found: {file_path}")
        try:
            name = file_path.relative_to(root).as_posix()
        except ValueError:
            raise ValueError(f"Output file is outside --files-root: {file_path}")
        loaded.append((name, file_path.read_bytes()))
    return loaded


def _extract_attestation_from_json(raw: str) -> str:
    """
    Extract base64 attestation document from raw input.

    Handles nested JSON structures from Epsilon job responses,
    or returns the input as-is if it's raw base64.
    """
    try:
        json_data = json.loads(raw)
        # Extract attestation document from nested structure
        if 'attestation' in json_data:
            if isinstance(json_data['attestation'], dict):
                if 'attestation' in json_data['attestation']:
                    if 'attestation_document' in json_data['attestation']['attestation']:
                        return json_data['attestation']['attestation']['attestation_document']
                if 'attestation_document' in json_data['attestation']:
                    return json_data['attestation']['attestation_document']
    except json.JSONDecodeError:
        pass
    return raw


def cmd_verify(args):
    """Verify an attestation document."""
    # Load attestation document
    attestation_path = Path(args.attestation)
    if not attestation_path.exists():
        print(f"Error: Attestation file not found: {attestation_path}", file=sys.stderr)
        return 1

    attestation_data = _extract_attestation_from_json(attestation_path.read_text().strip())

    # Load expected output
    expected_output = None
    if args.output:
        output_path = Path(args.output)
        if output_path.exists():
            expected_output = output_path.read_text()
        else:
            expected_output = args.output

    # Load expected output files (name = basename, or path relative to --files-root)
    expected_files = None
    if args.files or args.files_root:
        try:
            expected_files = _load_output_files(args.files, args.files_root)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

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
        expected_files=expected_files,
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
    print(f"Files Manifest:       {'✓' if result.files_verified else '✗'}")

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

    if result.files_manifest_sha256:
        print(f"\nFiles Manifest Hash: {result.files_manifest_sha256}")
    if result.expected_files_manifest_sha256:
        print(f"Expected:            {result.expected_files_manifest_sha256}")

    if result.user_data:
        print(f"\nUser Data:")
        for key, value in result.user_data.items():
            if key not in ('output_hash', 'files_manifest_sha256'):
                print(f"  {key}: {value}")

    print()


def cmd_list_versions(args):
    """List known enclave versions."""
    if args.fetch_latest:
        print("Fetching latest versions from GitHub...")
        latest = get_published_pcrs(fetch_latest=True)
        if latest:
            print(f"\nLatest from GitHub: {latest.version}")
            print(f"  PCR0: {latest.pcr0[:32]}...")
            if latest.release_date:
                print(f"  Released: {latest.release_date}")
        else:
            print("Failed to fetch versions from GitHub.")

    versions = list_known_versions()
    if not versions:
        print("No known versions in built-in registry.")
        if not args.fetch_latest:
            print("Use --fetch-latest to get versions from GitHub.")
        return 0

    print("\nBuilt-in Versions:" if args.fetch_latest else "Known Epsilon Enclave Versions:")
    for version in sorted(versions):
        pcrs = get_published_pcrs(version)
        if pcrs:
            print(f"\n  {version}")
            print(f"    PCR0: {pcrs.pcr0[:32]}...")
            if pcrs.release_date:
                print(f"    Released: {pcrs.release_date}")

    return 0


def cmd_code_digest(args):
    """Recompute the code digest (script_hash) from a job's build/ folder."""
    try:
        digest = compute_code_digest(args.build_dir)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(digest)
    if args.expect:
        if digest != args.expect.lower():
            print(f"MISMATCH: attested script_hash is {args.expect}", file=sys.stderr)
            return 1
        print("Matches the attested script_hash")
    return 0


def cmd_extract(args):
    """Extract information from attestation without verification."""
    attestation_path = Path(args.attestation)
    if not attestation_path.exists():
        print(f"Error: Attestation file not found: {attestation_path}", file=sys.stderr)
        return 1

    attestation_data = _extract_attestation_from_json(attestation_path.read_text().strip())

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
        'files_manifest_sha256': result.files_manifest_sha256,
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

  # Verify output files against the attested files manifest
  epsilon-verify verify attestation.json --files results.csv plot.png

  # Verify a whole outputs/ folder (names = paths relative to it, e.g. plots/fig1.png)
  epsilon-verify verify attestation.json --files-root outputs

  # Extract PCR values without verification
  epsilon-verify extract attestation.json

  # Recompute the code digest from the submitted commit's build/ folder
  epsilon-verify code-digest build --expect <script_hash from user_data>

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
    verify_parser.add_argument('--files', nargs='+', metavar='FILE',
                               help='Output files to check against the attested files manifest '
                                    '(named by basename, or by path relative to --files-root)')
    verify_parser.add_argument('--files-root', metavar='DIR',
                               help='Name output files by their path relative to DIR; '
                                    'without --files, check every file under DIR')
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

    # code-digest command
    digest_parser = subparsers.add_parser('code-digest',
                                          help="Recompute script_hash from a job's build/ folder")
    digest_parser.add_argument('build_dir', help="The build/ folder of the submitted commit")
    digest_parser.add_argument('--expect', metavar='SCRIPT_HASH',
                               help='Attested script_hash to compare with (exit 1 on mismatch)')

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
    elif args.command == 'code-digest':
        return cmd_code_digest(args)
    elif args.command == 'list-versions':
        return cmd_list_versions(args)
    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())
