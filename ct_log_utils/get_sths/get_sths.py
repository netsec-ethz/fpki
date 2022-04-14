#!/usr/bin/env python3

# this script is adapted from https://github.com/SSLMate/ct-honeybee. Original comment below:
#
# The Certificate Transparency Honeybee (ct-honeybee) is a lightweight
# program that retrieves signed tree heads (STHs) from Certificate
# Transparency logs and uploads them to auditors.
#
# You can help strengthen the integrity of the Certificate Transparency
# ecosystem by running ct-honeybee on your workstation/server/toaster every
# hour or so (pick a random minute so that not everyone runs ct-honeybee
# at the same time).  Running ct-honeybee from many different Internet
# vantage points increases the likelihood of detecting a misbehaving log
# which has presented a different view of the log to different clients.
#
# Written in 2017 by Opsmate, Inc. d/b/a SSLMate <sslmate@sslmate.com>
#
# To the extent possible under law, the author(s) have dedicated all
# copyright and related and neighboring rights to this software to the
# public domain worldwide. This software is distributed without any
# warranty.
#
# You should have received a copy of the CC0 Public
# Domain Dedication along with this software. If not, see
# <https://creativecommons.org/publicdomain/zero/1.0/>.
#


import json
import random
import re
import socket
import ssl
import sys
import time
import urllib.request

from pathlib import Path

version = '2021-09-14'
log_servers_file = 'honeybee.json'
log_timeout = 15

base64_re = re.compile('^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$')


def is_base64(obj):
	return isinstance(obj, str) and base64_re.search(obj) is not None


def is_sth(obj):
	return isinstance(obj, dict) \
	   and 'sth_version' in obj and isinstance(obj['sth_version'], int) \
	   and 'tree_size' in obj and isinstance(obj['tree_size'], int) \
	   and 'timestamp' in obj and isinstance(obj['timestamp'], int) \
	   and 'sha256_root_hash' in obj and is_base64(obj['sha256_root_hash']) \
	   and 'tree_head_signature' in obj and is_base64(obj['tree_head_signature']) \
	   and 'log_id' in obj and is_base64(obj['log_id'])


def main():
	sths = []
	logs = {}
	with open(Path(Path(__file__).parent,log_servers_file)) as f:
		d = json.load(f)['operators']
		for ee in d:
			for e in ee['logs']:
				if e['url'] in logs:
					raise ValueError(f'multiple entries: {e["url"]}')
				logs[e['url']] = e

	# Disable certificate validation. Unfortunately, there is no guarantee
	# that logs use a certificate from a widely-trusted CA. Fortunately,
	# all responses are signed by logs and verified by auditors, so there
	# is technically no need for certificate validation.
	try:
		_create_unverified_https_context = ssl._create_unverified_context
	except AttributeError:
		pass
	else:
		ssl._create_default_https_context = _create_unverified_https_context

	for log_url, e in logs.items():
		try:
			req = urllib.request.Request(log_url + 'ct/v1/get-sth',
							data=None, headers={'User-Agent': ''})
			with urllib.request.urlopen(req, timeout=log_timeout) as response:
				sth = json.loads(response.read().decode('utf-8'))
				if isinstance(sth, dict):
					sth['url'] = log_url
					sth['sth_version'] = 0
					sth['log_id'] = e['log_id']
					if is_sth(sth):
						sths.append(sth)
		except Exception as err:
			print('[%s] ct-honeybee: Log error: %s: %s: %s' %
				  (time.strftime('%Y-%m-%d %H:%M:%S %z'),
				  log_url,
				  type(err).__name__,
				  err), 
				  file=sys.stderr)

	print(json.dumps(sths, indent=4))


if __name__ == '__main__':
	main()
