#!/usr/bin/env python3
# i46641 full 65535 scan of the single in-scope host 40.160.14.146 from fresh GHA EIPs.
# Only this host (operator ClickHouse). Do NOT touch 40.160.14.0/24 neighbors (fact43311 out-of-scope).
import os, sys, socket, time, json, threading, urllib.request, urllib.parse

TARGET = "40.160.14.146"
JOB = str(os.environ.get("JOB", "0"))
TOPIC = os.environ.get("TOPIC", "i46641-clickops")

def log(*a): print(" ".join(str(x) for x in a), flush=True)
def send(tag, text):
    try:
        urllib.request.urlopen(urllib.request.Request("https://ntfy.sh/"+TOPIC,
            data=((("[j%s] "%JOB)+str(text)).encode("utf-8","replace")), method="POST",
            headers={"Title":("i46641-scan-"+tag)[:60]}), timeout=12).read()
    except Exception as e: log("NTFYERR", str(e)[:60])
def egress():
    for u in ("https://api.ipify.org","https://icanhazip.com"):
        try: return urllib.request.urlopen(u,timeout=10).read().decode().strip()
        except Exception: pass
    return "ERR"
def tcp(ip, port, t=1.5):
    try:
        s=socket.create_connection((ip,port),timeout=t); s.close(); return True
    except Exception: return False

def main():
    eg=egress(); log("EGRESS",eg)
    # control reachability (operator OVH segment reachable?)
    ctrl = tcp("40.160.50.80",3000,3.0)
    log("CONTROL 40.160.50.80:3000 OPEN=%s"%ctrl)
    send("start","job%s egress=%s control3000=%s fullscan %s"%(JOB,eg,ctrl,TARGET))
    openp=[]; lock=threading.Lock(); t0=time.time()
    def work(a,b):
        for port in range(a,b):
            if tcp(TARGET,port,1.5):
                with lock: openp.append(port); log("OPENPORT",port)
    N=900; step=65536//N; ths=[]
    for i in range(N):
        a=i*step; b=65536 if i==N-1 else (i+1)*step
        t=threading.Thread(target=work,args=(a,b)); t.start(); ths.append(t)
    for t in ths: t.join()
    openp.sort()
    log("FULLSCAN_DONE elapsed=%.0fs open=%s"%(time.time()-t0,openp))
    send("done","job%s FULLSCAN open=%s elapsed=%.0fs"%(JOB,openp,time.time()-t0))

if __name__=="__main__": main()
