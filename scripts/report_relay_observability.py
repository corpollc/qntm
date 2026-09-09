#!/usr/bin/env python3
"""Read deployed Worker logging settings without displaying bindings or secrets."""
import json
import os
import urllib.request

account = os.environ['CLOUDFLARE_ACCOUNT_ID']
token = os.environ['CLOUDFLARE_API_TOKEN']
request = urllib.request.Request(
    f'https://api.cloudflare.com/client/v4/accounts/{account}/workers/scripts/qntm-dropbox/settings',
    headers={'Authorization': 'Bearer ' + token},
)
with urllib.request.urlopen(request, timeout=20) as response:
    result = json.load(response)
if not result.get('success'):
    raise SystemExit('Unable to verify deployed Worker settings')
settings = result['result']
print(json.dumps({
    'worker': 'qntm-dropbox',
    'observability': settings.get('observability'),
    'logpush': settings.get('logpush'),
    'tail_consumer_services': [consumer.get('service') for consumer in settings.get('tail_consumers', [])],
    'scope': 'Worker settings only; account/zone exports and provider-internal retention are not audited here',
}, indent=2))
