#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, re, time, ssl, poplib, email, requests, hashlib
from email.header import decode_header, make_header
from email.utils import parsedate_to_datetime, parseaddr
from datetime import datetime, timezone, timedelta

# 先加载 .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ===================== 可调参数 =====================
FETCH_STARTUP_LAST_N = int(os.getenv("FETCH_STARTUP_LAST_N", "2"))   # 启动最多补扫 N 封
POLL_SECONDS         = float(os.getenv("POLL_SECONDS", "2"))
RECONNECT_EVERY      = float(os.getenv("RECONNECT_EVERY", "10"))
DEBUG_LOG            = os.getenv("DEBUG_LOG", "0") == "1"             # 可临时设 1 看选择路径

NEAR_KEYS = ["验证码","校验码","代码","code","verify","verification","登录","安全","2FA","OTP"]
CODE_RE   = re.compile(r"(?<!\d)(?:\d[\s-]?){4,8}(?!\d)")

EMSP = "\u2003"
GAP  = EMSP * 6
# ===================================================

# —— URL/Email 过滤工具 ——
_URL_RE   = re.compile(r'https?://[^\s<>"]+')
_EMAIL_RE = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')

def _overlaps(a_start, a_end, b_start, b_end):
    return not (a_end <= b_start or b_end <= a_start)

def _slice_window(text, s, e, extra=160):
    lo = max(0, s - extra); hi = min(len(text), e + extra)
    return text[lo:hi], lo, hi

def _in_url_or_email(hay, s, e):
    win, base, _ = _slice_window(hay, s, e, extra=200)
    for m in _URL_RE.finditer(win):
        if _overlaps(s, e, base+m.start(), base+m.end()):
            return True
    for m in _EMAIL_RE.finditer(win):
        if _overlaps(s, e, base+m.start(), base+m.end()):
            return True
    return False

# —— 基础工具 ——
def dec(s):
    if not s: return ""
    try: return str(make_header(decode_header(s)))
    except Exception: return s or ""

def body_text(msg):
    """优先 text/plain；回退 html→纯文本"""
    if msg.is_multipart():
        for p in msg.walk():
            if p.get_content_type()=="text/plain" and "attachment" not in str(p.get("Content-Disposition") or ""):
                try: return p.get_payload(decode=True).decode(p.get_content_charset() or "utf-8","ignore")
                except Exception: pass
        for p in msg.walk():
            if p.get_content_type()=="text/html":
                from html import unescape; import re as _r
                try:
                    h = p.get_payload(decode=True).decode(p.get_content_charset() or "utf-8","ignore")
                    return _r.sub(r"\s+"," ", _r.sub(r"<[^>]+>"," ", unescape(h)))
                except Exception: pass
    else:
        try: return msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8","ignore")
        except Exception: return ""
    return ""

# —— 时间：优先原始时区；缺省则北京 (+8) ——
def _bj_tz(): return timezone(timedelta(hours=8))

def _dt_from_mail(msg):
    raw = msg.get("Date")
    if not raw:
        return datetime.now(_bj_tz())
    dt = parsedate_to_datetime(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_bj_tz())
    return dt

def mail_time_str_ymd(msg):
    try: return _dt_from_mail(msg).strftime("%Y年%m月%d日 %H:%M")
    except Exception: return datetime.now(_bj_tz()).strftime("%Y年%m月%d日 %H:%M")

# —— POP3/TG ——
def send_tg(token, chat_id, text, proxy=None):
    if not token or not chat_id or not text: return
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    proxies = {"http":proxy,"https":proxy} if proxy else None
    try: requests.post(url, data={"chat_id":chat_id,"text":text}, timeout=10, proxies=proxies)
    except Exception as e: print("Telegram 推送失败：", e)

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

# —— 辅助：判断 openai 发件人 ——
def _is_openai_sender(frm: str) -> bool:
    _, addr = parseaddr(frm or "")
    dom = (addr.split("@")[-1] if "@" in addr else "").lower()
    return any(x in dom for x in ("openai.com", "tm.openai.com", "tm1.openai.com"))

# —— 核心：稳定提取验证码（支持 OpenAI 专项） ——
def extract_code(text: str, subject: str = "", frm: str = ""):
    body = text or ""
    subj = subject or ""

    # 0) OpenAI 专项：只认 6 位；先看 Subject，再看正文强模板，再看同一行/近邻
    if _is_openai_sender(frm):
        # a) Subject 直接 6 位
        m = re.search(r"(?<!\d)(\d{6})(?!\d)", subj)
        if m:
            if DEBUG_LOG: print("[extract] openai -> subject")
            return m.group(1)

        # b) 正文强模板（中英）
        pats = [
            r"(?:chatgpt|openai).{0,40}?(?:验证码|代码|verification(?:\s*code)?|code).{0,20}?(\d{6})",
            r"(?:verification\s*code|your\s*code).{0,20}?(\d{6})",
            r"(?:请输入|使用|输入).{0,30}?(\d{6}).{0,20}?(?:验证码|code|代码)"
        ]
        for pat in pats:
            mm = re.search(pat, body, re.IGNORECASE | re.DOTALL)
            if mm:
                if DEBUG_LOG: print("[extract] openai -> strong pattern")
                return mm.group(1)

        # c) 正文同一行含关键词，取 6 位，并过滤 URL/邮箱
        base = 0
        for line in body.splitlines(True):
            pure = line.rstrip("\r\n")
            low  = pure.lower()
            if any(k.lower() in low for k in NEAR_KEYS):
                m2 = re.search(r"(?<!\d)(\d{6})(?!\d)", pure)
                if m2:
                    s,e = m2.span()
                    s_glob, e_glob = base + s, base + e
                    if not _in_url_or_email(body, s_glob, e_glob):
                        if DEBUG_LOG: print("[extract] openai -> same-line 6d")
                        return m2.group(1)
            base += len(line)

        # d) 近邻 6 位（过滤 URL/邮箱）
        for mm in re.finditer(r"(?<!\d)(\d{6})(?!\d)", body):
            s,e = mm.span()
            win = body[max(0,s-30):min(len(body),e+30)].lower()
            if any(k.lower() in win for k in NEAR_KEYS):
                if not _in_url_or_email(body, s, e):
                    if DEBUG_LOG: print("[extract] openai -> window 6d")
                    return mm.group(1)

        if DEBUG_LOG: print("[extract] openai -> no 6d hit")
        return None  # openai 一律不要非 6 位

    # 1) 非 openai：先“同一行 + 关键词”（过滤 URL/邮箱）
    base = 0
    for line in body.splitlines(True):
        pure = line.rstrip("\r\n")
        low  = pure.lower()
        if any(k.lower() in low for k in NEAR_KEYS):
            m = CODE_RE.search(pure)
            if m:
                s_local, e_local = m.span()
                s_glob, e_glob   = base + s_local, base + e_local
                if not _in_url_or_email(body, s_glob, e_glob):
                    if DEBUG_LOG: print("[extract] same-line")
                    return re.sub(r"[\s-]", "", m.group())
        base += len(line)

    # 2) 再“±30 窗口内有关键词”（过滤 URL/邮箱）
    for mm in CODE_RE.finditer(body):
        s, e = mm.span()
        win = body[max(0, s-30):min(len(body), e+30)].lower()
        if any(k.lower() in win for k in NEAR_KEYS):
            if not _in_url_or_email(body, s, e):
                if DEBUG_LOG: print("[extract] window")
                return re.sub(r"[\s-]", "", mm.group())

    return None  # 不再回退“第一个数字”
# ===================================================

def startup_flag_path(user):
    key = hashlib.sha1(user.encode("utf-8")).hexdigest()[:12]
    return os.path.join(os.getcwd(), f".startup_done_{key}.flag")

def send_meta_then_code(token, chat, frm, to, ts, code, proxy=None):
    line1 = f"📬 {ts}  {frm} → {to}"
    send_tg(token, chat, line1, proxy)
    send_tg(token, chat, code, proxy)

def run_session(host, user, pwd, token, chat, proxy, seen_uids):
    srv = connect_pop3(
        host, user, pwd,
        int(os.getenv("POP3_PORT_SSL","995")),
        int(os.getenv("POP3_PORT_PLAIN","110"))
    )
    total, _ = srv.stat()

    m0 = uidl_map(srv)
    baseline_total = None

    # —— 启动阶段：最多读取最近 N 封（已见去重） ——
    if FETCH_STARTUP_LAST_N > 0 and total > 0:
        start = max(1, total - FETCH_STARTUP_LAST_N + 1)
        if m0:
            for num in range(start, total+1):
                uid = m0.get(num)
                if not uid or uid in seen_uids:
                    continue
                try:
                    msg   = fetch_msg(srv, num)
                    subj  = dec(msg.get("Subject"))
                    frm   = dec(msg.get("From")) or ""
                    text  = body_text(msg)
                    code  = extract_code(text, subj, frm)
                    if code:
                        ts   = mail_time_str_ymd(msg)
                        to   = dec(msg.get("To")) or user
                        send_meta_then_code(token, chat, frm, to, ts, code, proxy)
                        try: open("latest_code.txt","w",encoding="utf-8").write(code)
                        except Exception: pass
                    seen_uids.add(uid)
                except Exception as e:
                    print("历史邮件处理失败：", e)
        else:
            flag = startup_flag_path(user)
            if not os.path.exists(flag):
                for num in range(start, total+1):
                    try:
                        msg   = fetch_msg(srv, num)
                        subj  = dec(msg.get("Subject"))
                        frm   = dec(msg.get("From")) or ""
                        text  = body_text(msg)
                        code  = extract_code(text, subj, frm)
                        if code:
                            ts   = mail_time_str_ymd(msg)
                            to   = dec(msg.get("To")) or user
                            send_meta_then_code(token, chat, frm, to, ts, code, proxy)
                            try: open("latest_code.txt","w",encoding="utf-8").write(code)
                            except Exception: pass
                    except Exception as e:
                        print("历史邮件处理失败：", e)
                try: open(flag,"w").write("done")
                except Exception: pass
            baseline_total = total

    if m0:
        seen_uids.update(m0.values())

    # —— 轮询（只处理新邮件） ——
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
                subj = dec(msg.get("Subject"))
                frm  = dec(msg.get("From")) or ""
                text = body_text(msg)
                code = extract_code(text, subj, frm)
                if code:
                    ts   = mail_time_str_ymd(msg)
                    to   = dec(msg.get("To")) or user
                    send_meta_then_code(token, chat, frm, to, ts, code, proxy)
                    try: open("latest_code.txt","w",encoding="utf-8").write(code)
                    except Exception: pass
                uid = (m.get(num) if m else f"no-uidl-{num}")
                seen_uids.add(uid)

            time.sleep(POLL_SECONDS)

        except poplib.error_proto as e:
            print("[POP3] 会话异常，切换到重连…", e); break
        except Exception as e:
            print("错误：", e); time.sleep(POLL_SECONDS)

    try: srv.quit()
    except Exception: pass

def main():
    host  = os.getenv("POP3_HOST","pop3.2925.com").strip()
    user  = os.getenv("EMAIL_USER","")
    pwd   = os.getenv("EMAIL_PASS","")
    token = os.getenv("TELEGRAM_BOT_TOKEN","")
    chat  = os.getenv("TELEGRAM_CHAT_ID","")
    proxy = os.getenv("TG_PROXY") or None

    try:
        send_tg(token, chat, "✅ POP3 验证码监听已启动。（启动补扫 2 封；时间=邮件原始/无则北京；OpenAI 仅 6 位，优先 Subject）", proxy)
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


