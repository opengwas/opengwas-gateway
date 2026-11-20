#!/usr/bin/env python3
"""
End-to-end smoke test: the gateway in front of the real Data API (ogdb).

Start the gateway with its real config, Neo4j, Redis and Data API, then run:

    OPENGWAS_JWT=<a user's token> GATEWAY_SERVICE_KEY=<a service key> \\
        venv/bin/python scripts/smoke.py --gateway http://localhost:8000

Credentials are read from the environment only and never printed. Either may
be left out; the checks that need it are then skipped. It checks one request
of each kind, not every endpoint: the gateway routes every path the same way.

  public   the service index, the served spec and docs, and 401 without a token
  status   X-Request-ID round trip; X-Allowance-* present and counting (JWT)
  user     /api/user says the role is 'gateway'
  catalog  /api/gwasinfo answers at once
  data     a job: 202 with a cost estimate and /ogdb links, polled to the end,
           the measured cost header, every result page and its checksum.
           Sent with a fake X-OGDB-User and X-Forwarded-Prefix, which the
           gateway must replace
  ld       the same for an LD matrix job
  errors   an unknown endpoint gets 501; an oversized query gets error/message

Exit status 1 if any check fails. Jobs are keyed by user and query, so a rerun
within a few minutes may get the same finished job back ('existing').
"""

import argparse
import hashlib
import json
import os
import sys
import time
import uuid

import httpx

DATA_QUERY = {   # the PheWAS example from ogdb-api's README; served on the dev deployment
    'endpoint': '/api/phewas',
    'variant': '7:105920689:A:G',
    'releases': [{'store_id': 'OGS-00024', 'release_id': 'OGS-00024'}],
    'limit': 100,
}
LD_QUERY = {     # the LD matrix example from ogdb-api's docs/guide/ld.qmd
    'ancestry': 'EUR',
    'alids': ['7:105919152:C:T', '7:105920446:A:G', '7:105920689:A:G', '7:110998200:C:T'],
}
PREFIX = '/ogdb'
TERMINAL = {'succeeded', 'failed', 'cancelled', 'expired'}


class Results:
    def __init__(self):
        self.failed = 0

    def check(self, mode: str, name: str, ok: bool, detail: object = '') -> bool:
        if not ok:
            self.failed += 1
        print(f"{'PASS' if ok else 'FAIL'}  {mode:7} {name}{f'  ({detail})' if detail != '' else ''}")
        return ok

    def skip(self, mode: str, name: str, why: str) -> None:
        print(f"SKIP  {mode:7} {name}  ({why})")


def _json(response: httpx.Response) -> dict:
    try:
        body = response.json()
        return body if isinstance(body, dict) else {}
    except ValueError:
        return {}


def check_public(client: httpx.Client, r: Results) -> None:
    resp = client.get('/')
    names = [s.get('name') for s in _json(resp).get('services', [])]
    r.check('public', 'index lists ogdb', resp.status_code == 200 and 'ogdb' in names, names)

    resp = client.get(f'{PREFIX}/openapi.json')
    spec = _json(resp)
    ops = [op for item in spec.get('paths', {}).values() for m, op in item.items()
           if m in {'get', 'put', 'post', 'delete', 'patch'}]
    r.check('public', 'spec served under /ogdb',
            resp.status_code == 200 and spec.get('servers') == [{'url': PREFIX}],
            f"{resp.status_code}, servers={spec.get('servers')}")
    missing = sum('429' not in op.get('responses', {}) for op in ops)
    r.check('public', 'every operation documents 429', ops and not missing,
            f'{len(ops)} operations, {missing} without')
    headers = set(spec.get('components', {}).get('headers', {}))
    r.check('public', 'X-Allowance-* documented',
            {'X-Allowance-Limit', 'X-Allowance-Remaining', 'X-Allowance-Reset'} <= headers)

    resp = client.get('/docs', params={'service': 'ogdb'})
    r.check('public', 'docs page', resp.status_code == 200 and 'swagger' in resp.text.lower(),
            resp.status_code)

    resp = client.get(f'{PREFIX}/api/status')
    r.check('public', '401 without a token', resp.status_code == 401, resp.status_code)
    resp = client.get(f'{PREFIX}/api/status', headers={'Authorization': 'Bearer not-a-jwt'})
    r.check('public', '401 with a bad token', resp.status_code == 401, resp.status_code)


def check_status(client: httpx.Client, r: Results, mode: str, limited: bool) -> None:
    request_id = f'smoke-{uuid.uuid4().hex[:12]}'
    resp = client.get(f'{PREFIX}/api/status', headers={'X-Request-ID': request_id})
    r.check(mode, 'status 200', resp.status_code == 200, resp.status_code)
    r.check(mode, 'X-Request-ID echoed', resp.headers.get('X-Request-ID') == request_id,
            resp.headers.get('X-Request-ID'))
    resp = client.get(f'{PREFIX}/api/status', headers={'X-Request-ID': 'not valid!'})
    r.check(mode, 'invalid X-Request-ID replaced',
            resp.headers.get('X-Request-ID') not in (None, 'not valid!'), resp.headers.get('X-Request-ID'))

    remaining = resp.headers.get('X-Allowance-Remaining')
    if not limited:
        r.check(mode, 'no X-Allowance-* (not rate-limited)', remaining is None, remaining)
        return
    if not r.check(mode, 'X-Allowance-* present', remaining is not None,
                   remaining if remaining is not None else 'absent: is this IP in RATE_LIMIT_EXEMPT_CIDRS?'):
        return
    again = client.get(f'{PREFIX}/api/status').headers.get('X-Allowance-Remaining')
    r.check(mode, 'allowance counts down by 1', again is not None and int(again) == int(remaining) - 1,
            f'{remaining} then {again}')


def check_user(client: httpx.Client, r: Results, mode: str) -> None:
    resp = client.get(f'{PREFIX}/api/user')
    body = _json(resp)
    r.check(mode, "/api/user role is 'gateway'", resp.status_code == 200 and body.get('role') == 'gateway',
            f"{resp.status_code}, user={body.get('user')}, role={body.get('role')}, tier={body.get('tier')}")


def check_catalog(client: httpx.Client, r: Results, mode: str) -> None:
    resp = client.get(f'{PREFIX}/api/gwasinfo', params={'limit': 1})
    r.check(mode, 'gwasinfo answers at once', resp.status_code == 200, resp.status_code)


def run_job(client: httpx.Client, r: Results, mode: str, label: str, path: str, body: dict,
            timeout: float) -> None:
    # A client's own X-OGDB-User and X-Forwarded-Prefix must be replaced by the gateway.
    resp = client.post(path, json=body, headers={'X-OGDB-User': 'smoke-spoofed-user',
                                                 'X-Forwarded-Prefix': '/spoofed'})
    accepted = _json(resp)
    if resp.status_code in (404, 501) and accepted.get('error') != 'not_found':
        r.skip(mode, f'{label} job', f"{resp.status_code} {accepted.get('error') or resp.text[:80]}: "
                                     'not served here; pass another query')
        return
    if not r.check(mode, f'{label}: 202', resp.status_code == 202,
                   f"{resp.status_code} {accepted.get('error', '')} {accepted.get('message', '')}".strip()):
        return
    job_id = accepted.get('job_id')
    location = resp.headers.get('Location', '')
    r.check(mode, f'{label}: Location and status_url under /ogdb',
            location.startswith(f'{PREFIX}/api/jobs/') and accepted.get('status_url') == location,
            location)
    estimate = resp.headers.get('X-OGDB-Cost-Estimate')
    cost_on_202 = resp.headers.get('X-OGDB-Cost')   # a resubmission of a finished job
    r.check(mode, f'{label}: cost estimate on 202',
            (estimate or '').isdigit() or (accepted.get('existing') and cost_on_202),
            f"estimate={estimate}, existing={accepted.get('existing')}")

    # Poll without the spoofed header: if the gateway had passed it on, the job
    # would belong to 'smoke-spoofed-user' and this would be 404.
    deadline = time.monotonic() + timeout
    while True:
        resp = client.get(location)
        status = _json(resp)
        if resp.status_code != 200 or status.get('status') in TERMINAL or time.monotonic() > deadline:
            break
        wait = resp.headers.get('Retry-After') or status.get('poll_after_seconds') or 2
        time.sleep(min(float(wait), 10))
    r.check(mode, f'{label}: job owned by the real user (spoofed X-OGDB-User dropped)',
            resp.status_code == 200, resp.status_code)
    if not r.check(mode, f'{label}: succeeded', status.get('status') == 'succeeded',
                   f"{status.get('status')} {status.get('error') or ''}".strip()):
        return
    cost = resp.headers.get('X-OGDB-Cost', '')
    r.check(mode, f'{label}: X-OGDB-Cost names the job', f'job="{job_id}"' in cost, cost or 'absent')

    result_url = (status.get('result') or {}).get('result_url', '')
    r.check(mode, f'{label}: result_url under /ogdb', result_url.startswith(f'{PREFIX}/api/jobs/'),
            result_url)
    pages = rows = bad = 0
    params = {}
    while True:
        resp = client.get(result_url, params=params)
        page = _json(resp)
        if resp.status_code != 200:
            r.check(mode, f'{label}: result page {pages + 1}', False,
                    f"{resp.status_code} {page.get('error', resp.text[:80])}")
            return
        ndjson = page.get('ndjson', '')
        digest = hashlib.sha256(ndjson.encode()).hexdigest()
        bad += not str(page.get('sha256', '')).endswith(digest)
        pages += 1
        rows += sum(1 for line in ndjson.splitlines() if line.strip())
        if page.get('final') or not page.get('next_cursor'):
            break
        params = {'cursor': page['next_cursor']}
    r.check(mode, f'{label}: every page read, checksums match', not bad,
            f'{pages} pages, {rows} rows, {bad} bad checksums')


def check_errors(client: httpx.Client, r: Results, mode: str) -> None:
    # The one documented exception to JSON errors: an operation the Stores cannot
    # serve answers 501 with the plain text 'Not yet implemented'.
    resp = client.post(f'{PREFIX}/api/jobs', json={'endpoint': '/api/does-not-exist'})
    r.check(mode, 'unknown endpoint: 501 Not yet implemented',
            resp.status_code == 501 and resp.text.strip() == 'Not yet implemented',
            f'{resp.status_code} {resp.text[:40]!r}')

    resp = client.post(f'{PREFIX}/api/jobs', json={
        'endpoint': '/api/associations', 'analyses': ['smoke'],
        'variants': [f'1:{1_000_000 + i}:A:G' for i in range(1001)]})
    error = _json(resp)
    r.check(mode, 'oversized query: refused with error and message',
            400 <= resp.status_code < 500 and resp.status_code != 429 and 'error' in error
            and 'message' in error,
            f"{resp.status_code} {error.get('error')}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--gateway', default='http://localhost:8000', help='gateway base URL')
    parser.add_argument('--data-query', type=json.loads, default=DATA_QUERY,
                        help='JSON body for POST /ogdb/api/jobs (default: a PheWAS on OGS-00024)')
    parser.add_argument('--ld-query', type=json.loads, default=LD_QUERY,
                        help='JSON body for POST /ogdb/api/ld/matrix')
    parser.add_argument('--job-timeout', type=float, default=300, help='seconds to wait for each job')
    args = parser.parse_args()

    modes = []
    if os.environ.get('OPENGWAS_JWT'):
        modes.append(('jwt', {'Authorization': f"Bearer {os.environ['OPENGWAS_JWT']}"}, True))
    if os.environ.get('GATEWAY_SERVICE_KEY'):
        modes.append(('service', {'X-Service-Key': os.environ['GATEWAY_SERVICE_KEY']}, False))

    r = Results()
    with httpx.Client(base_url=args.gateway, timeout=60) as client:
        check_public(client, r)
    if not modes:
        r.skip('-', 'authenticated checks', 'set OPENGWAS_JWT and/or GATEWAY_SERVICE_KEY')
    for mode, headers, limited in modes:
        with httpx.Client(base_url=args.gateway, timeout=60, headers=headers) as client:
            check_status(client, r, mode, limited)
            check_user(client, r, mode)
            check_catalog(client, r, mode)
            run_job(client, r, mode, 'data', f'{PREFIX}/api/jobs', args.data_query, args.job_timeout)
            run_job(client, r, mode, 'ld', f'{PREFIX}/api/ld/matrix', args.ld_query, args.job_timeout)
            check_errors(client, r, mode)

    print(f"\n{'FAILED: ' + str(r.failed) + ' check(s)' if r.failed else 'All checks passed.'}")
    return 1 if r.failed else 0


if __name__ == '__main__':
    sys.exit(main())
