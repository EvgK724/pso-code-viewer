#!/usr/bin/env python3
"""Prepare a separate static release for a chosen HTTPS origin/API.

No network, server changes, secrets, patient data or private-key migration.
The source directory is never modified; the output directory must not exist.
Python 3.7+ standard library only.
"""
import argparse
import html
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from urllib.parse import urlsplit, urlunsplit


ENDPOINTS = {
    'SHORTLINK_ENDPOINT': 'pso-shortlinks',
    'PUSH_ENDPOINT': 'pso-push',
    'TEAM_ENDPOINT': 'pso-team',
    'DIRECT_ENDPOINT': 'pso-direct',
    'DEVICE_AUTH_ENDPOINT': 'pso-device-auth',
}


def https_base(value):
    if not isinstance(value, str) or not value or any(c.isspace() for c in value):
        raise ValueError('Use an HTTPS URL without spaces.')
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or
            parsed.password or parsed.query or parsed.fragment):
        raise ValueError('HTTPS URLs must not contain credentials, query or fragment.')
    try:
        port = parsed.port
    except ValueError:
        raise ValueError('Invalid HTTPS port.')
    host = parsed.hostname.lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', p) for p in host.split('.')):
            raise ValueError('Use a valid ASCII/punycode hostname.')
    if port is not None and not 1 <= port <= 65535:
        raise ValueError('Invalid HTTPS port.')
    path = parsed.path or '/'
    if (not re.fullmatch(r'/[A-Za-z0-9._~/-]*', path) or '//' in path or
            any(p in ('.', '..') for p in path.split('/'))):
        raise ValueError('Use a canonical path without percent escapes or traversal segments.')
    if not path.endswith('/'):
        path += '/'
    netloc = ('[' + host + ']') if ':' in host else host
    if port is not None and port != 443:
        netloc += ':' + str(port)
    return urlunsplit(('https', netloc, path, '', ''))


def origin(value):
    p = urlsplit(value)
    return urlunsplit((p.scheme, p.netloc, '', '', ''))


def prepare(source, output, viewer_base, api_base):
    source, output = Path(source).resolve(), Path(output).resolve()
    viewer_base, api_base = https_base(viewer_base), https_base(api_base)
    if not source.is_dir():
        raise ValueError('Static source directory does not exist.')
    if output.exists():
        raise ValueError('Output already exists. Choose a new empty release path.')
    if output == source or source in output.parents:
        raise ValueError('Output must be outside the static source directory.')
    for name in ('index.html', 'shortlink-config.mjs', 'manifest.webmanifest', 'sw.js'):
        if not (source / name).is_file():
            raise ValueError('Static release is incomplete: ' + name)
    if any(path.is_symlink() for path in source.rglob('*')):
        raise ValueError('Static source must not contain symbolic links.')
    source_html = (source / 'index.html').read_text(encoding='utf-8')
    pattern = re.compile(r'(<meta\s+http-equiv=[\"\']Content-Security-Policy[\"\']\s+content=)([\"\'])(.*?)\2', re.I | re.S)
    match = pattern.search(source_html)
    if match is None or len(pattern.findall(source_html)) != 1:
        raise ValueError('Expected exactly one Content-Security-Policy meta tag.')
    policy = html.unescape(match.group(3))
    directives = [item.strip() for item in policy.split(';') if item.strip()]
    if len([item for item in directives if item.split()[0] == 'connect-src']) != 1:
        raise ValueError('Expected one explicit connect-src policy.')
    directives = ["connect-src 'self' " + origin(api_base) if item.split()[0] == 'connect-src' else item for item in directives]
    policy = '; '.join(directives)
    updated_html = pattern.sub(lambda m: m.group(1) + '"' + html.escape(policy, quote=True) + '"', source_html)
    manifest = json.loads((source / 'manifest.webmanifest').read_text(encoding='utf-8'))
    # This app's links and service worker are path-relative. A different origin
    # intentionally creates a distinct app/keystore; it never imports old keys.
    manifest.update({'id': './', 'start_url': './', 'scope': './'})
    for icon in manifest.get('icons', []):
        src = icon.get('src', '')
        if not isinstance(src, str) or src.startswith(('/', 'http:', 'https:', '//')) or '..' in src.split('/'):
            raise ValueError('Manifest icons must be local, path-relative assets.')
    config = '// Public service addresses. No secret or private key belongs here.\n'
    config += ''.join('export const {} = {};\n'.format(name, json.dumps(api_base + route)) for name, route in ENDPOINTS.items())
    services = {'team_endpoint': api_base + 'pso-team', 'direct_endpoint': api_base + 'pso-direct', 'viewer_url': viewer_base}
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix='.pso-hosting-', dir=str(output.parent)))
    try:
        shutil.copytree(str(source), str(temporary / 'docs'))
        (temporary / 'docs' / 'index.html').write_text(updated_html, encoding='utf-8')
        (temporary / 'docs' / 'shortlink-config.mjs').write_text(config, encoding='utf-8')
        (temporary / 'docs' / 'manifest.webmanifest').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        (temporary / 'service-config.json').write_text(json.dumps(services, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        (temporary / 'hosting.env.example').write_text('# Public origin only. Set backend secrets separately in the hosting platform.\nPSO_VIEWER_ORIGIN=' + origin(viewer_base) + '\n', encoding='utf-8')
        headers = (
            '# Apply these as HTTP response headers on the static viewer host.\n'
            '# This file is documentation, not a universal host configuration.\n'
            'Content-Security-Policy: ' + policy + "; frame-ancestors 'none'\n"
            'Referrer-Policy: no-referrer\n'
            'X-Content-Type-Options: nosniff\n'
            'X-Frame-Options: DENY\n'
            'Permissions-Policy: geolocation=(), microphone=(), camera=(self)\n'
            'Strict-Transport-Security: max-age=31536000\n'
            '\n# index.html, manifest.webmanifest and sw.js:\n'
            'Cache-Control: no-cache\n'
            '\n# All API responses (including errors):\n'
            'Cache-Control: no-store\n'
        )
        (temporary / 'security-headers.txt').write_text(headers, encoding='utf-8')
        (temporary / 'RELEASE.txt').write_text(
            'Prepared static copy only; nothing has been deployed.\n'
            'Viewer: ' + viewer_base + '\nAPI base: ' + api_base + '\n'
            'Publish the contents of docs/ at the chosen viewer path.\n'
            'Copy service-config.json only into the NEW viewer bot package.\n'
            'A changed origin requires new device enrollment and a new passkey.\n'
            'Do not copy or export browser private keys.\n'
            'Read server/HOSTING-MIGRATION.md before deployment.\n', encoding='utf-8')
        if output.exists():
            raise ValueError('Output appeared during preparation. Nothing was overwritten.')
        os.replace(str(temporary), str(output))
    finally:
        if temporary.exists():
            shutil.rmtree(str(temporary))
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1] / 'docs')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--viewer-base', required=True, help='Dedicated HTTPS viewer URL, e.g. https://viewer.example/pso/')
    parser.add_argument('--api-base', required=True, help='HTTPS edge function base, e.g. https://api.example/functions/v1/')
    args = parser.parse_args()
    try:
        result = prepare(args.source, args.output, args.viewer_base, args.api_base)
    except (ValueError, OSError, json.JSONDecodeError) as error:
        parser.exit(2, 'Not prepared: ' + str(error) + '\n')
    print('Prepared copy: ' + str(result))
    print('No server, DNS or existing installation was changed.')


if __name__ == '__main__':
    main()
