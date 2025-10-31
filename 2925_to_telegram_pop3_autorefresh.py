#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
可用环境变量（都可不设，用默认值）：
- TIME_SOURCE   : 'received' | 'date'       # 时间来源，默认 received（顶层 Received）
- TIME_TZ       : 'Asia/Shanghai'           # 目标显示时区，默认北京时间
- TIME_CONVERT  : '1' 或 '0'                # 是否把邮件头时间换算到目标时区，默认 1
- TIME_FMT      : strftime 格式             # 默认 "%Y年%m月%d日 %H:%M"
"""

import os, re, time, ssl, poplib, email, requests, hashlib
from email.header import decode_header, make_header
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone, timedelta

# ====== 可调参数 ======
FETCH_STARTUP_LAST_N = 2   # 启动时最多读取 2 条历史验证码（仅一次）
POLL_SECONDS = 2           # 轮询间隔（秒）
RECONNECT_EVERY = 10       # 每 10 秒强制重连
# 大间隔（EM 空格 U+2003），复制时也保留空格
EMSP = "\u2003"
GAP = EMSP * 6             # 想再宽就调这个数字
# =====================

NEAR_KEYS = ["验证码","校验码","code","verify","verification","登录","安全","2FA","OTP"]
CODE_RE = re.compile(r"(?<!\d)(?:\d[\s-]?){4,8}(?!\d)")

# ---------- 时区/显示参数 ----------
TIME_SOURCE  = os.getenv("TIME_SOURCE", "received").lower()   # 'received' or 'date'
TIME_CONVERT = os.getenv("TIME_CONVERT", "1") == "1"
TIME_FMT     = os.getenv("TIME_FMT", "%Y年%m月%d日 %H:%M")
# 目标时区
try:
    from zoneinfo import ZoneInfo
    TARGET_TZ = ZoneInfo(os.getenv("TIME_TZ", "Asia/Shanghai"))
except Exception:
    TARGET_TZ = timezone(timedelta(hours=8))  # 兜底：东八区
# ----------------------------------

def dec(s):
    if not s: return ""
    try:
        return str(make_header(decode_header(s)))
    except Exception:
        return s or ""

def body_text(msg):
    if msg.is_multipart():
        for p in msg.walk():
            if p.get_content_type()=="text/plain" and "attachment" not in str(p.get("Content-Disposition") or ""):
                try:
                    return p.get_payload(decode=True).decode(p.get_content_charset() or "utf-8","ignore")
                except Exception:
                    pass
        for p in msg.walk():
            if p.get_content_type()=="text/html":
                from html import unescape; import re as _r
                try:
                    h = p.get_payload(decode=True).decode(p.get_content_charset() or "utf-8","ignore")
                    return _r.sub(r"\s+"," ", _r.sub(r"<[^>]+>"," ", unescape(h)))
                except Exception:
                    pass
    else:
        try:
            return msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8","ignore")
        except Exception:
            return ""
    return ""

# ------------------- 时间：优先顶层 Received（收件服务器），否则 Date -------------------
def _parse_received_dt(msg):
    """返回顶层 Received 分号后的时间（datetime），解析失败返回 None"""
    try:
        recvs = msg.get_all('Received') or []
        for r in recvs:  # 顶层在前，越靠前越新（更接近“邮箱收到时间”）
            tstr = r.rsplit(';', 1)[-1].strip() if ';' in r else r.strip()
            try:
                return parsedate_to_datetime(tstr)
            except Exception:
                continue
    except Exception:
        pass
    return None

def _parse_date_dt(msg):
    try:
        raw = msg.get("Date")
        if raw:
            return parsedate_to_datetime(raw)
    except Exception:
        pass
    return None

def _to_target_tz(dt):
    """按配置换算到目标时区；若无 tz 且需要换算，则视为目标时区"""
    if not isinstance(dt, datetime):
        return None
    if TIME_CONVERT:
        # 需要换算：无 tz 直接视作目标时区，有 tz 则 astimezone
        if dt.tzinfo is None:
            return dt.replace(tzinfo=TARGET_TZ)
        return dt.astimezone(TARGET_TZ)
    else:
        # 不换算：无 tz 时也不补 tz，原样返回
        return dt

def mail_time_str_ymd(msg):
    """
    返回“邮箱收到时间”（优先顶层 Received），并按配置换算到目标时区；
    格式由 TIME_FMT 控制，默认：YYYY年MM月DD日 HH:MM（北京时间）。
    """
    dt = None
    if TIME_SOURCE == "received":
        dt = _parse_received_dt(msg) or _parse_date_dt(msg)
    else:
        dt = _parse_date_dt(msg) or _parse_received_dt(msg)

    if dt is None:
        dt = datetime.now(TARGET_TZ) if TIME_CONVERT else datetime.now()

    dt2 = _to_target_tz(dt) or dt
    return dt2.strftime(TIME_FMT)
# ------------------------------------------------------------------------------------

def send_tg(token, chat_id, text, proxy=None):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    proxies = {"http":proxy,"https":proxy} if proxy else None
    try:
        requests.post(url, data={"chat_id":chat_id,"text":text}, timeout=10, proxies=proxies)
    except Exception as e:
        print("Telegram 推送失败：", e)

def connect_pop3(host, user, pwd, port_ssl=995, port_plain=110):
    try:
        ctx = ssl.create_default_context()
        srv = poplib.POP3_SSL(host, port_ssl, context=ctx, timeout=10)
        srv.user(user); srv.pass_(pwd)
        print("[POP3] 995/SSL")
        return srv
    except Exception as e:
        print("[POP3] 995 失败，用 110+STLS/PLAIN：", e)
        srv = poplib.POP3(host, port_plain, timeout=10)
        try:
            srv.stls(); print("[POP3] 110 已升级 STLS")
        except Exception:
            print("[POP3] 110 明文（仅在可信网络用）")
        srv.user(user); srv.pass_(pwd)
        return srv

def uidl_map(srv):
    try:
        resp, lst, _ = srv.uidl(); m={}
        for line in lst or []:
            parts = line.decode("utf-8","ignore").split()
            if len(parts)>=2: m[int(parts[0])] = parts[1]
        return m
    except Exception:
        return {}

def fetch_msg(srv, num):
    resp, lines, _ = srv.retr(num)
    raw = b"\r\n".join(lines)
    return email.message_from_bytes(raw)

def extract_code(text):
    ctx=[]
    for mm in CODE_RE.finditer(text or ""):
        s,e=mm.span()
        win = (text or "")[max(0,s-30):min(len(text or ""),e+30)].lower()
        if any(k.lower() in win for k in NEAR_KEYS):
            ctx.append(mm.group())
    hit = ctx[0] if ctx else (CODE_RE.search(text or "") and CODE_RE.search(text or "").group())
    import re as _r
    return _r.sub(r"[\s-]","",hit) if hit else None

def startup_flag_path(user):
    """无 UIDL 时防重复：用账号生成唯一 flag 文件名"""
    key = hashlib.sha1(user.encode("utf-8")).hexdigest()[:12]
    return os.path.join(os.getcwd(), f".startup_done_{key}.flag")

# ---------- 两条消息：第一条元信息，第二条纯验证码 ----------
def send_meta_then_code(token, chat, frm, to, ts, code, proxy=None):
    meta = f"📬 {ts}{GAP}{frm} → {to}"
    send_tg(token, chat, meta, proxy)
    send_tg(token, chat, code, proxy)
# ------------------------------------------------------------

def run_session(host, user, pwd, token, chat, proxy, seen_uids):
    srv = connect_pop3(host, user, pwd,
                       int(os.getenv("POP3_PORT_SSL","995")), int(os.getenv("POP3_PORT_PLAIN","110")))
    total, _ = srv.stat()

    # ---------------- 启动阶段：最多读取最近 N 封，但要去重 ----------------
    m0 = uidl_map(srv)
    baseline_total = None
    if FETCH_STARTUP_LAST_N > 0 and total > 0:
        start = max(1, total - FETCH_STARTUP_LAST_N + 1)
        if m0:
            for num in range(start, total+1):
                uid = m0.get(num)
                if not uid or uid in seen_uids:
                    continue
                try:
                    msg  = fetch_msg(srv, num)
                    text = body_text(msg)
                    code = extract_code(text or "")
                    if code:
                        ts  = mail_time_str_ymd(msg)
                        frm = dec(msg.get("From")) or "(unknown)"
                        to  = dec(msg.get("To")) or user
                        send_meta_then_code(token, chat, frm, to, ts, code, proxy)
                        try:
                            with open("latest_code.txt","w",encoding="utf-8") as f: f.write(code)
                        except Exception:
                            pass
                    seen_uids.add(uid)
                except Exception as e:
                    print("历史邮件处理失败：", e)
        else:
            flag = startup_flag_path(user)
            if not os.path.exists(flag):
                for num in range(start, total+1):
                    try:
                        msg  = fetch_msg(srv, num)
                        text = body_text(msg)
                        code = extract_code(text or "")
                        if code:
                            ts  = mail_time_str_ymd(msg)
                            frm = dec(msg.get("From")) or "(unknown)"
                            to  = dec(msg.get("To")) or user
                            send_meta_then_code(token, chat, frm, to, ts, code, proxy)
                            try:
                                with open("latest_code.txt","w",encoding="utf-8") as f: f.write(code)
                            except Exception:
                                pass
                    except Exception as e:
                        print("历史邮件处理失败：", e)
                try:
                    with open(flag, "w") as f: f.write("done")
                except Exception:
                    pass
            baseline_total = total
    # --------------------------------------------------------------------

    if m0:
        seen_uids.update(m0.values())

    # ======================= 轮询阶段（只处理新邮件） ======================
    t0 = time.time()
    while True:
        if time.time() - t0 >= RECONNECT_EVERY:
            break
        try:
            m = uidl_map(srv)
            if m:
                new_nums = [n for n,u in sorted(m.items()) if u not in seen_uids]
            else:
                cur_total, _ = srv.stat()
                if baseline_total is None:
                    baseline_total = cur_total
                new_nums = list(range(baseline_total+1, cur_total+1))
                baseline_total = cur_total

            for num in new_nums[-20:]:
                msg  = fetch_msg(srv, num)
                text = body_text(msg)
                code = extract_code(text or "")
                if code:
                    ts  = mail_time_str_ymd(msg)
                    frm = dec(msg.get("From")) or "(unknown)"
                    to  = dec(msg.get("To")) or user
                    send_meta_then_code(token, chat, frm, to, ts, code, proxy)
                    try:
                        with open("latest_code.txt","w",encoding="utf-8") as f: f.write(code)
                    except Exception:
                        pass

                uid = (m.get(num) if m else f"no-uidl-{num}")
                seen_uids.add(uid)

            time.sleep(POLL_SECONDS)

        except poplib.error_proto as e:
            print("[POP3] 会话异常，切换到重连…", e); break
        except Exception as e:
            print("错误：", e); time.sleep(POLL_SECONDS)
    # =====================================================================

    try: srv.quit()
    except Exception:
        pass

def main():
    # 读 .env
    try:
        from dotenv import load_dotenv; load_dotenv()
    except Exception:
        pass
    host  = os.getenv("POP3_HOST","pop3.2925.com").strip()
    user  = os.getenv("EMAIL_USER","")
    pwd   = os.getenv("EMAIL_PASS","")
    token = os.getenv("TELEGRAM_BOT_TOKEN","")
    chat  = os.getenv("TELEGRAM_CHAT_ID","")
    proxy = os.getenv("TG_PROXY") or None

    # 启动提示
    try:
        send_tg(token, chat, "✅ POP3 验证码监听已启动。（开机最多读 2 条历史）", proxy)
    except Exception as e:
        print("❌ Telegram 失败：", e)

    seen_uids = set()
    while True:
        try:
            run_session(host, user, pwd, token, chat, proxy, seen_uids)
        except KeyboardInterrupt:
            print("\n已退出。"); break
        except Exception as e:
            print("重连失败：", e)
        time.sleep(1)

if __name__ == "__main__":
    main()


