"""Check the non-secret Connection metadata before uploading the customer pack."""

import argparse
import json
import ssl
import urllib.error
import urllib.request
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--middleware-url', default='https://127.0.0.1:5200')
    parser.add_argument('--api-key-file', type=Path)
    parser.add_argument('--insecure', action='store_true', help='Allow a local self-signed TLS certificate')
    args = parser.parse_args()
    headers = {}
    if args.api_key_file:
        headers['X-API-Key'] = args.api_key_file.read_text().strip()
    url = args.middleware_url.rstrip('/') + '/api/v1/workflows/connections/external?include_credentials=false'
    context = ssl._create_unverified_context() if args.insecure else ssl.create_default_context()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), context=context, timeout=10) as response:
            connection = json.load(response)
    except (urllib.error.URLError, ValueError) as exc:
        raise SystemExit(f'external Connection lookup failed: {type(exc).__name__}') from None
    if (connection.get('conn_type'), connection.get('schema')) != ('mysql', 'external'):
        raise SystemExit('external Connection must be MySQL with schema external')
    if not connection.get('host') or not connection.get('login'):
        raise SystemExit('external Connection has incomplete non-secret fields')
    print('external Connection preflight: OK')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
