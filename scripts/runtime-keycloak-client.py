#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit local core client registration. Never modifies identities or other clients."""
import json
import os
from pathlib import Path
import stat
import urllib.request
import urllib.parse
import urllib.error

ROOT=Path(__file__).resolve().parents[1]
ORIGIN='http://localhost:4311'
CLIENT={'clientId':'governance-protected-web','protocol':'openid-connect','name':'Governance Commons protected login','enabled':True,'publicClient':True,
 'standardFlowEnabled':True,'directAccessGrantsEnabled':False,'serviceAccountsEnabled':False,
 'redirectUris':['http://127.0.0.1:4310/authn/callback'],'webOrigins':['http://127.0.0.1:4310'],
 'attributes':{'pkce.code.challenge.method':'S256'}}
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise ValueError('Redirect refused')
def request(path,method='GET',body=None,token=None,form=False):
 if not path.startswith('/') or '\n' in path or '\r' in path:raise ValueError()
 headers={'Content-Type':'application/x-www-form-urlencoded' if form else 'application/json'}
 if token:headers['Authorization']='Bearer '+token
 data=None if body is None else (urllib.parse.urlencode(body) if form else json.dumps(body)).encode()
 with urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect()).open(urllib.request.Request(ORIGIN+path,data=data,headers=headers,method=method),timeout=15) as response:
  raw=response.read(65537)
  if len(raw)>65536:raise ValueError()
  return json.loads(raw) if raw else None

def matches(row):
 return (isinstance(row,dict) and all(type(row.get(k)) is type(v) and row.get(k)==v for k,v in CLIENT.items() if k!='attributes')
  and isinstance(row.get('attributes'),dict) and row['attributes'].get('pkce.code.challenge.method')=='S256'
  and row.get('implicitFlowEnabled',False) is False and row.get('bearerOnly',False) is False
  and row.get('consentRequired',False) is False)

def main():
 from runtime import require_local,require_bootstrap
 require_bootstrap();require_local()
 fd=os.open(ROOT/'.local/bootstrap.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  metadata=os.fstat(fd)
  if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=os.getuid() or stat.S_IMODE(metadata.st_mode)!=0o600 or not 0<metadata.st_size<=65536:raise ValueError()
  with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(65537)
  after=os.fstat(fd)
  if len(raw)!=metadata.st_size or (metadata.st_mtime_ns,metadata.st_ctime_ns)!=(after.st_mtime_ns,after.st_ctime_ns):raise ValueError()
  values=json.loads(raw)
 finally:os.close(fd)
 response=request('/realms/master/protocol/openid-connect/token','POST',{'grant_type':'password','client_id':'admin-cli','username':'local-admin','password':values['KEYCLOAK_ADMIN_PASSWORD']},form=True)
 token=response.get('access_token') if isinstance(response,dict) else None
 if not isinstance(token,str) or not 1<=len(token)<=32768:raise ValueError()
 path='/admin/realms/governance/clients?clientId=governance-protected-web'
 rows=request(path,token=token)
 if rows==[]:
  request('/admin/realms/governance/clients','POST',CLIENT,token)
  rows=request(path,token=token)
 if not isinstance(rows,list) or len(rows)!=1 or not matches(rows[0]):raise ValueError()
 print('Protected local OIDC client: verified. Existing users and other clients were preserved.')
if __name__=='__main__':
 try:main()
 except Exception:raise SystemExit('Protected local OIDC client not confirmed. Inspect the intended local client; no existing client or identity was overwritten. Private credentials were not logged.')
