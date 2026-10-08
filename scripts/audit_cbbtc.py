#!/usr/bin/env python3
"""Read-only, block-pinned Base cbBTC cross-venue audit. No execution-profit claim."""
import argparse,json,urllib.request,time,itertools,concurrent.futures,threading
from pathlib import Path
from Cryptodome.Hash import keccak
U="0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"; B="0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf"; E="0x4200000000000000000000000000000000000006"
PM="0x498581ff718922c3f8e6a244956af099b2652b2b"; Q4="0x0d5e0f971ed27fbff6c2837bf31316121532048d"; Q3="0x3d4e44eb1374240ce5f1b871ab261cd16335b76a"; QS="0x254cf9e1e6e233aa1ac962cb9b05b2cfeaae15b0"
EXTRA_QUOTERS=["0x3d4c22254f86f64b7ec90ab8f7aec1fbfd271c6c","0x514c8b5f54112481e28028f1166bd78501089259"]
REG="0x5c3f18f06cc09ca1910767a34a20f771039e37c0"; F3="0x33128a8fc17869897dce68ed026d694621f6fdfd"
TARGETS=[("0x64f978ef116d3c2e1231cfd8b80a369dcd8e91b28037c9973b65b59fd2cbbb96","0x5cd525c621afca515bf58631d4733fba7b72aae4",3000,200),("0xdfb2536ba09a004b32db0a1a15f73676b5e356d831c4ea1e843cd9433b080ab6","0x9d11f9505ca92f4b6983c1285d1ac0aaff7ec0c0",8388608,10)]
def kh(b):
 h=keccak.new(digest_bits=256);h.update(b);return h.digest()
def w(x):return (x%(1<<256)).to_bytes(32,"big")
def aw(a):return bytes.fromhex(a[2:]).rjust(32,b"\0")
def data(sig,*args):return "0x"+(kh(sig.encode())[:4]+b"".join(args)).hex()
def words(s):return [int(s[i:i+64],16) for i in range(2,len(s),64)]
def address(x):return "0x"+f"{x:040x}"
def valid_hook(h,fee):
 f=int(h,16)&16383
 if int(h,16)==0:return fee!=8388608
 return all(not(f&(1<<a)) or bool(f&(1<<b)) for a,b in [(3,7),(2,6),(1,10),(0,8)]) and (bool(f) or fee==8388608)
class RPC:
 def __init__(self,url,interval=0.2):
  self.url=url;self.block="latest";self.calls=[];self.interval=interval;self.lock=threading.Lock();self.next_request=0
 def rpc(self,m,p):
  for attempt in range(3):
   try:
    with self.lock:
     time.sleep(max(0,self.next_request-time.monotonic()));self.next_request=time.monotonic()+self.interval
    req=urllib.request.Request(self.url,json.dumps(dict(jsonrpc="2.0",id=1,method=m,params=p)).encode(),{"Content-Type":"application/json","User-Agent":"Mozilla/5.0"})
    with urllib.request.urlopen(req,timeout=20) as r:out=json.load(r)
    self.calls.append(dict(method=m,params=p,response=out))
    if "error" in out:raise ValueError(str(out["error"]))
    return out["result"]
   except (OSError,TimeoutError):
    if attempt==2:raise
    time.sleep(2**attempt)
 def call(self,a,d):return words(self.rpc("eth_call",[{"to":a,"data":d},self.block]))
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--resume",action="store_true");ap.add_argument("--rpc",default="https://mainnet.base.org");ap.add_argument("--request-interval",type=float,default=0.2);ap.add_argument("--output",default="research/cbbtc/latest.json");args=ap.parse_args();r=RPC(args.rpc,args.request_interval)
 out={"status":{"hook_rebate":"NO: no rebate demonstrated","cross_venue":"INCONCLUSIVE","atomic_simulation":"NOT_RUN"},"errors":[],"pools":[],"v4":[],"quotes":[],"routes":[]}
 def safe(fn,context):
  try:return fn()
  except Exception as e:out["errors"].append({"context":context,"error":str(e)});return None
 if args.resume:
  out=json.loads(Path(args.output).read_text());r.block=out["block"]["number"];quoter_factories=out["quoter_factories"]
  header=r.rpc("eth_getBlockByNumber",[r.block,False])
  if header["hash"]!=out["block"]["hash"]:raise ValueError("resume block hash mismatch")
  out.setdefault("previous_rpc",[]).append(out["rpc"]);out["rpc"]=args.rpc
  out["previous_errors"]=out.get("previous_errors",[])+out.get("errors",[]);out["errors"]=[];out["routes"]=[];out["completed"]=False
  out["quote_coverage"]={"successful_quotes":len(out["quotes"]),"successful_routes":0,"failed_calls":0,"exhaustive":False}
 else:
  r.block=hex(int(r.rpc("eth_blockNumber",[]),16)-5);out["block"]=r.rpc("eth_getBlockByNumber",[r.block,False]);out["rpc"]=args.rpc
  for a,dec in [(U,6),(B,8),(E,18)]:
   actual=r.call(a,data("decimals()"))[0]
   if actual!=dec:raise ValueError("canonical token decimals mismatch")
  quoter_factories={q:address(r.call(q,data("factory()"))[0]) for q in [Q3,QS]};out["quoter_factories"]=quoter_factories
  factories=r.call(REG,data("poolFactories()"));factories=[address(x) for x in factories[2:2+factories[1]]];out["approved_factories"]=factories
  for pid,h,fee,ts in TARGETS:
   key=aw(U)+aw(B)+w(fee)+w(ts)+aw(h)
   assert "0x"+kh(key).hex()==pid
   base=int.from_bytes(kh(bytes.fromhex(pid[2:])+w(6)),"big")
   slot=safe(lambda:r.call(PM,data("extsload(bytes32)",w(base)))[0],pid)
   if slot is not None:
    tick=(slot>>160)&0xffffff;tick=tick-(1<<24) if tick&(1<<23) else tick
    sqrt=slot&((1<<160)-1)
    out["v4"].append(dict(pool_id=pid,hook=h,fee=fee,tick_spacing=ts,valid_permission_bits=valid_hook(h,fee),tick=tick,protocol_fee=(slot>>184)&0xffffff,lp_fee=(slot>>208)&0xffffff,usdc_per_cbbtc=(2**192/sqrt**2)*100 if sqrt else None))
  pairs=[(U,B),(U,E),(E,B)]; jobs=[]
  for a,b in pairs:
   for f in [100,200,500,1000,3000,10000]:jobs.append(("v3",F3,a,b,f,"getPool(address,address,uint24)"))
   for fac in factories:
    for n in [0,1]:
     for sig in ["getPool(address,address,bool)","getPool(address,address,uint24)"]:jobs.append(("classic",fac,a,b,n,sig))
    for n in [1,10,50,100,200,500,1000,2000]:jobs.append(("slipstream",fac,a,b,n,"getPool(address,address,int24)"))
  def discover(job):
   typ,fac,a,b,n,sig=job
   try:
    ret=r.call(fac,data(sig,aw(a),aw(b),w(n)))
    if not ret or not ret[0]:return
    pool=address(ret[0]);tokens=[address(r.call(pool,data("token0()"))[0]),address(r.call(pool,data("token1()"))[0])]
    if set(tokens)!={a,b} or address(r.call(pool,data("factory()"))[0])!=fac:raise ValueError("pool identity mismatch")
    actual=r.call(pool,data("stable()" if typ=="classic" else "fee()" if typ=="v3" else "tickSpacing()"))[0]
    if actual!=n:raise ValueError("pool parameter mismatch")
    return dict(type=typ,factory=fac,address=pool,tokens=tokens,parameter=n)
   except Exception as e:
    return {"discovery_error":str(e),"job":job}
  with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:results=list(ex.map(discover,jobs))
  out["discovery_failures"]=[p for p in results if p and "discovery_error" in p]
  seen=set()
  for p in results:
   if p and "address" in p and p["address"] not in seen:out["pools"].append(p);seen.add(p["address"])
  print("discovered",len(out["pools"]),"pools",flush=True)
  out["coverage"]={"v3_fees":[100,200,500,1000,3000,10000],"slipstream_tick_spacings":[1,10,50,100,200,500,1000,2000],"exhaustive":False}
 for q in EXTRA_QUOTERS:
  factory=safe(lambda:address(r.call(q,data("factory()"))[0]),"quoter factory "+q)
  if factory:quoter_factories[q]=factory
 out["quoter_factories"]=quoter_factories
 saved_calls=len(r.calls)
 out["raw_rpc_calls"]=out.get("raw_rpc_calls",[])+r.calls[:saved_calls]
 def checkpoint():
  nonlocal saved_calls
  out["raw_rpc_calls"].extend(r.calls[saved_calls:]);saved_calls=len(r.calls)
  path=Path(args.output);path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(out,indent=2)+"\n")
 checkpoint()
 cache={(q["pool"],q["token_in"],q["token_out"],q["amount_in"]):q["amount_out"] for q in out["quotes"]}
 def quote(p,a,b,amt):
  k=(p.get("address",p.get("pool_id")),a,b,amt)
  if k in cache:return cache[k]
  def run():
   if "pool_id" in p:
    enc=aw(U)+aw(B)+w(p["fee"])+w(p["tick_spacing"])+aw(p["hook"])+w(a==U)+w(amt)+w(256)+w(0)
    res=r.call(Q4,data("quoteExactInputSingle(((address,address,uint24,int24,address),bool,uint128,bytes))",w(32),enc))
   elif p["type"]=="classic":res=r.call(p["address"],data("getAmountOut(uint256,address)",w(amt),aw(a)))
   else:
    t="uint24" if p["type"]=="v3" else "int24";q=Q3 if t=="uint24" else QS
    q=next((candidate for candidate,factory in quoter_factories.items() if factory==p["factory"]),None)
    if q is None:raise ValueError("quoter factory mismatch; unsupported factory")
    res=r.call(q,data(f"quoteExactInputSingle((address,address,uint256,{t},uint160))",aw(a),aw(b),w(amt),w(p["parameter"]),w(0)))
   if not res or res[0]<=0:raise ValueError("empty/zero quote")
   out["quotes"].append(dict(pool=k[0],token_in=a,token_out=b,amount_in=amt,amount_out=res[0],return_words=res));return res[0]
  cache[k]=safe(run,str(k));return cache[k]
 def legs(a,b):return [p for p in out["pools"] if set(p["tokens"])=={a,b}]
 routes=[[(p,U,B)] for p in legs(U,B)]+[[(p,U,E),(q,E,B)] for p,q in itertools.product(legs(U,E),legs(E,B))]
 for usd in [25,100,1000,10000]:
  amt=usd*10**6
  for v in out["v4"]:
   buy=quote(v,U,B,amt)
   def evaluate(route):
    for direction in ["v4_buy","v4_sell"]:
     cur=buy if direction=="v4_buy" else amt
     ordered=[(p,b,a) for p,a,b in reversed(route)] if direction=="v4_buy" else route
     for p,a,b in ordered:
      if cur is None:break
      cur=quote(p,a,b,cur)
     if cur is not None and direction=="v4_sell":cur=quote(v,B,U,cur)
     if cur is not None:out["routes"].append(dict(usdc_in=usd,v4=v["pool_id"],direction=direction,venues=[p["address"] for p,_,_ in route],usdc_out=cur/1e6,gross_bps=(cur/amt-1)*10000,atomic_verified=False))
   with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:list(ex.map(evaluate,routes))
  checkpoint()
  print("quoted",usd,"USDC",flush=True)
 topic="0x"+kh(b"Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)").hex()
 out["swap_window"]={"from_block":int(r.block,16)-1999,"to_block":int(r.block,16)}
 prior_logs={json.dumps(c["params"],sort_keys=True):c["response"]["result"] for c in out.get("raw_rpc_calls",[]) if c["method"]=="eth_getLogs" and "result" in c["response"]}
 out["swap_log_coverage"]={}
 for pid,_,_,_ in TARGETS:
  logs=[];successful_chunks=0
  for start in range(int(r.block,16)-1999,int(r.block,16)+1,500):
   params=[{"address":PM,"fromBlock":hex(start),"toBlock":hex(min(start+499,int(r.block,16))),"topics":[topic,pid]}]
   cache_key=json.dumps(params,sort_keys=True)
   part=prior_logs[cache_key] if cache_key in prior_logs else safe(lambda:r.rpc("eth_getLogs",params),"Swap logs "+pid)
   if part is not None:logs.extend(part);successful_chunks+=1
  out["swap_log_coverage"][pid]={"successful_chunks":successful_chunks,"total_chunks":4,"complete":successful_chunks==4}
  out.setdefault("swap_logs",{})[pid]=logs
 out["completed"]=True
 out["raw_rpc_calls"].extend(r.calls[saved_calls:]);saved_calls=len(r.calls)
 out["quote_coverage"]={"successful_quotes":len(out["quotes"]),"successful_routes":len(out["routes"]),"failed_calls":len(out["errors"]),"exhaustive":False}
 path=Path(args.output);path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(out,indent=2)+"\n")
 print(json.dumps({"block":int(r.block,16),"pools":len(out["pools"]),"routes":len(out["routes"]),"errors":len(out["errors"]),"best":sorted(out["routes"],key=lambda x:x["gross_bps"],reverse=True)[:3]},indent=2))
if __name__=="__main__":main()
