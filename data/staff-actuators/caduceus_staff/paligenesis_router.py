"""Paligenesis router convergence preserves install versus provisioned-verify variants."""
from __future__ import annotations
import argparse, hashlib, json, os, subprocess, tempfile, time
from pathlib import Path
from typing import Sequence
SCHEMA="caduceus.paligenesis.router.v1"
def run(argv:list[str])->dict:
 p=subprocess.run(argv,text=True,capture_output=True,check=False);return {"argv":argv,"exit":p.returncode,"stdout":p.stdout.strip(),"stderr":p.stderr.strip()}
def fingerprint(root:Path)->str:
 h=hashlib.sha256(); paths=[root/"cli.py"]
 for directory in (root/"daemon",root/"install"):
  if directory.exists(): paths.extend(directory.rglob("*"))
 for path in sorted(paths):
  if path.is_file():h.update(str(path.relative_to(root)).encode()+b"\0");h.update(oct(path.stat().st_mode&0o777).encode()+b"\0");h.update(path.read_bytes())
 return h.hexdigest()
def ready(endpoint:str,timeout:int)->bool:
 end=time.monotonic()+timeout
 while time.monotonic()<end:
  if run(["curl","-fsS",endpoint])["exit"]==0:return True
  time.sleep(1)
 return False
def atomic(path:Path,value:str)->None:
 path.parent.mkdir(parents=True,exist_ok=True)
 with tempfile.NamedTemporaryFile("w",encoding="utf-8",dir=path.parent,prefix=f".{path.name}.",delete=False) as out:out.write(value+"\n");out.flush();os.fsync(out.fileno());tmp=Path(out.name)
 os.replace(tmp,path)
def converge(variant:str,plan:bool,source:Path,state:Path,endpoint:str,timeout:int)->dict:
 stamp=state/("installed.sha256" if variant=="laptop-01" else "verified.sha256");digest=fingerprint(source);service=run(["systemctl","is-active","--quiet","paligenesis.service"]);current=stamp.is_file() and stamp.read_text().strip()==digest and service["exit"]==0
 commands=[]
 if variant=="laptop-01" and not (source/"cli.py").is_file():commands.append(["runuser","-u","owner","--","/fulcrum/cli.py","lib","paligenesis","summon"])
 if variant=="laptop-01":commands.append(["runuser","-u","owner","--","/fulcrum/cli.py","lib","paligenesis","install"])
 commands.append(["systemctl","enable","--now","paligenesis.service"])
 answer={"schema":SCHEMA,"ok":True,"variant":variant,"planned":plan,"changed":not current,"source":str(source),"fingerprint":digest,"stamp":str(stamp),"endpoint":endpoint,"commands":commands,"firstMissingSignal":"none"}
 if plan:return answer
 if variant=="laptop-02" and not (source/"cli.py").is_file():return {**answer,"ok":False,"firstMissingSignal":"paligenesis-router-source-unprovisioned"}
 if variant=="laptop-02" and service["exit"]!=0:return {**answer,"ok":False,"firstMissingSignal":"paligenesis-router-service-unprovisioned"}
 outcomes=[] if current else [run(x) for x in commands]
 if any(x["exit"] for x in outcomes):return {**answer,"ok":False,"results":outcomes,"firstMissingSignal":"paligenesis-router-command-failed"}
 if not ready(endpoint,timeout):return {**answer,"ok":False,"results":outcomes,"firstMissingSignal":"paligenesis-router-readiness-timeout"}
 atomic(stamp,digest);return {**answer,"results":outcomes,"changed":not current}
def main(argv:Sequence[str]|None=None)->int:
 p=argparse.ArgumentParser(prog="caduceus-paligenesis-router");p.add_argument("variant",choices=("laptop-01","laptop-02"));p.add_argument("--plan",action="store_true");p.add_argument("--source",type=Path,default=Path(os.environ.get("PALIGENESIS_SOURCE_ROOT","/fulcrum/attachments/paligenesis")));p.add_argument("--state",type=Path,default=Path(os.environ.get("PALIGENESIS_STATE_DIR","/var/lib/harmonia/paligenesis-router")));p.add_argument("--endpoint",default=os.environ.get("PALIGENESIS_ENDPOINT","http://127.0.0.1:4141/api/v1/status"));p.add_argument("--timeout",type=int,default=int(os.environ.get("PALIGENESIS_READINESS_TIMEOUT_SECS","60")));a=p.parse_args(argv);v=converge(a.variant,a.plan,a.source,a.state,a.endpoint,a.timeout);print(json.dumps(v,sort_keys=True));return 0 if v["ok"] else 42 if v["firstMissingSignal"].endswith("unprovisioned") else 1
if __name__=="__main__":raise SystemExit(main())
