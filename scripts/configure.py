#!/usr/bin/env python3
"""Generate a private self-hosted configuration; never print secrets."""
import argparse,os,secrets,re
from pathlib import Path
from urllib.parse import urlsplit
p=argparse.ArgumentParser();p.add_argument('--url',required=True);p.add_argument('--admin',default='owner');args=p.parse_args();u=urlsplit(args.url)
if u.scheme!='https' or not u.hostname or u.username or u.password or u.query or u.fragment or u.path not in ('','/') or any(c in args.url for c in '\r\n'):p.error('--url must be an HTTPS origin')
if not re.fullmatch(r'[A-Za-z0-9_.-]{2,80}',args.admin):p.error('Invalid administrator username')
os.umask(0o077);dest=Path(__file__).resolve().parents[1]/'.env'
values={'PUBLIC_URL':args.url.rstrip('/'),'ADMIN_USER':args.admin,'ADMIN_PASSWORD':secrets.token_urlsafe(24),'AGENT_SECRET':secrets.token_hex(32),'JWT_SECRET':secrets.token_hex(32),'HERMES_API_TOKEN':'','OPENAI_API_KEY':'','OPENAI_MODEL':'gpt-4.1-mini','RMM_BIND_ADDRESS':'127.0.0.1','RMM_PORT':'8080','RUSTDESK_HOST':'','RUSTDESK_KEY':''}
with dest.open('x') as f:f.write(''.join(k+'='+v+'\n' for k,v in values.items()))
print('Created .env with mode 0600. Retrieve the initial password locally using your secure editor. Never commit this file.')
