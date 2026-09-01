#!/usr/bin/env python3
import hashlib, json, os, re, sys, tomllib
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen
API="https://git.home.arpa/api/v1"; OWNER="HOMESERVERSLTD"; REPO="caduceus"; SCHEMA="caduceus.forgejo-release-publish.v1"
class ReleaseError(RuntimeError): pass

def api(method,path,token,body=None,data=None,query=None,binary=False):
    url=API+path+(("?"+urlencode(query)) if query else "")
    h={"Accept":"application/octet-stream" if binary else "application/json","Authorization":"token "+token}
    if body is not None: data=json.dumps(body).encode(); h["Content-Type"]="application/json"
    elif data is not None: h["Content-Type"]="application/octet-stream"
    try:
        with urlopen(Request(url,data=data,headers=h,method=method),timeout=60) as r:
            b=r.read()
            if binary: return r.status,b
            try: return r.status,(json.loads(b) if b else None)
            except json.JSONDecodeError: return r.status,b
    except HTTPError as e: return e.code,None
    except (OSError,URLError,TimeoutError) as e: raise ReleaseError("forgejo-transport-"+type(e).__name__) from e

def absolute(url,token):
    if not isinstance(url,str) or not url.startswith("https://git.home.arpa/"): raise ReleaseError("asset-download-url-invalid")
    try:
        with urlopen(Request(url,headers={"Accept":"application/octet-stream","Authorization":"token "+token}),timeout=60) as r: return r.status,r.read()
    except HTTPError as e: return e.code,None
    except (OSError,URLError,TimeoutError) as e: raise ReleaseError("forgejo-transport-"+type(e).__name__) from e

def digest(p):
    h=hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda:f.read(1048576),b""): h.update(b)
    return h.hexdigest()

def identity(root):
    try:
        m=json.loads((root/".release/cargo-metadata.json").read_text()); c=tomllib.loads((root/"Cargo.toml").read_text())
    except (OSError,json.JSONDecodeError,tomllib.TOMLDecodeError) as e: raise ReleaseError("build-metadata-read-"+type(e).__name__) from e
    p=c.get("package"); bins=c.get("bin",[])
    if not isinstance(p,dict) or not isinstance(bins,list) or len(bins)!=1 or not isinstance(bins[0],dict): raise ReleaseError("cargo-toml-must-declare-one-binary")
    v=n=None
    v=p.get("version"); n=bins[0].get("name")
    if not isinstance(v,str) or not v or not isinstance(n,str) or not n: raise ReleaseError("cargo-toml-binary-identity-missing")
    ps=m.get("packages",[]); td=m.get("target_directory")
    if not isinstance(ps,list) or len(ps)!=1 or not isinstance(td,str): raise ReleaseError("cargo-metadata-package-shape-invalid")
    mt=ps[0]; ts=mt.get("targets",[]) if isinstance(mt,dict) else []
    bs=[x for x in ts if isinstance(x,dict) and "bin" in x.get("kind",[])]
    if mt.get("version")!=v or len(bs)!=1 or bs[0].get("name")!=n: raise ReleaseError("cargo-metadata-does-not-match-one-binary")
    b=root/td/"release"/n
    if not b.is_file(): raise ReleaseError("release-binary-missing")
    return v,n,b

def verify(assets,artifact,sidecar,token,want=None):
    if not isinstance(assets,list): raise ReleaseError("release-assets-invalid")
    a={x.get("name"):x for x in assets if isinstance(x,dict) and isinstance(x.get("name"),str)}
    if artifact not in a or sidecar not in a: raise ReleaseError("release-assets-incomplete")
    def get(x):
        u=x.get("browser_download_url") or x.get("url"); s,b=absolute(u,token)
        if s!=200 or not isinstance(b,bytes): raise ReleaseError("asset-download-failed")
        return b
    remote=hashlib.sha256(get(a[artifact])).hexdigest()
    if want is not None and remote!=want: raise ReleaseError("release-binary-digest-mismatch")
    if get(a[sidecar])!=(remote+"  "+artifact+"\n").encode(): raise ReleaseError("release-sidecar-mismatch")
    return remote

def tagsha(x):
    if not isinstance(x,dict): return None
    x=x.get("commit",x); return x.get("sha") or x.get("id") or x.get("target") if isinstance(x,dict) else None

def publish(root,token):
    if os.environ.get("CI_REPO") not in (None,OWNER+"/"+REPO): raise ReleaseError("CI_REPO-mismatch")
    commit=os.environ.get("CI_COMMIT_SHA","")
    if not re.fullmatch(r"[0-9a-fA-F]{40}",commit): raise ReleaseError("CI_COMMIT_SHA-missing-or-invalid")
    if not token: raise ReleaseError("FORGEJO_TOKEN-missing")
    v,n,b=identity(root); artifact=f"{n}-{v}-x86_64"; sidecar=artifact+".sha256"; want=digest(b)
    base=f"/repos/{quote(OWNER,safe='')}/{quote(REPO,safe='')}"; q=quote(v,safe='')
    s,r=api("GET",base+"/releases/tags/"+q,token)
    if s==200:
        if not isinstance(r,dict) or r.get("id") is None: raise ReleaseError("release-read-failed")
        s,a=api("GET",base+f"/releases/{r['id']}/assets",token)
        if s!=200: raise ReleaseError("release-assets-read-failed")
        remote=verify(a,artifact,sidecar,token)
        return {"schema":SCHEMA,"repository":OWNER+"/"+REPO,"status":"no-op","changed":False,"version":v,"tag":v,"artifact":artifact,"sha256":remote}
    if s!=404: raise ReleaseError("release-read-failed")
    s,t=api("GET",base+"/tags/"+q,token)
    if s==200:
        if tagsha(t)!=commit: raise ReleaseError("tag-conflicts-with-source-head")
    elif s!=404: raise ReleaseError("tag-read-failed")
    tag_exists=s==200
    changed=False
    if not tag_exists:
        s,_=api("POST",base+"/tags",token,body={"tag_name":v,"target":commit})
        if s not in (200,201): raise ReleaseError("tag-create-failed")
        changed=True
    s,r=api("POST",base+"/releases",token,body={"tag_name":v,"name":v,"body":"caduceus "+v,"draft":False,"prerelease":False})
    if s not in (200,201) or not isinstance(r,dict) or r.get("id") is None: raise ReleaseError("release-create-failed")
    rid=r['id']; changed=True
    for name,data in ((artifact,b.read_bytes()),(sidecar,(want+"  "+artifact+"\n").encode())):
        s,_=api("POST",base+f"/releases/{rid}/assets",token,data=data,query={"name":name})
        if s not in (200,201): raise ReleaseError("asset-upload-failed")
    s,a=api("GET",base+f"/releases/{rid}/assets",token)
    if s!=200: raise ReleaseError("release-assets-reread-failed")
    verify(a,artifact,sidecar,token,want)
    return {"schema":SCHEMA,"repository":OWNER+"/"+REPO,"status":"published","changed":changed,"version":v,"tag":v,"artifact":artifact,"sha256":want}

def main():
    try: out=publish(Path(os.environ.get("CI_WORKSPACE",".")).resolve(),os.environ.get("FORGEJO_TOKEN","")); code=0
    except (OSError,ValueError,ReleaseError) as e: out={"schema":SCHEMA,"repository":OWNER+"/"+REPO,"status":"error","changed":False,"error":str(e)}; code=1
    print(json.dumps(out,sort_keys=True,separators=(",",":"))); return code
if __name__=="__main__": sys.exit(main())
