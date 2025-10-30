#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, re, time, ssl, poplib, email, requests, hashlib
from email.header import decode_header, make_header
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone

# 尝试最早加载 .env，使下方的 os.getenv 能读取到
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ===================== 可调参数（均可用环境变量覆盖） =====================
FETCH_STARTUP_LAST_N = int(os.getenv("FETCH_STARTUP_LAST_N", "2"))   # 启动最多补扫 N 封（仅一次）
POLL_SECONDS         = float(os.getenv("POLL_SECONDS", "2"))         # 轮询间隔（秒）
RECONNECT_EVERY      = float(os.getenv("RECONNECT_EVERY", "10"))     # 每隔 N 秒强制重连

# 识别相关
OTP_MIN, OTP_MAX     = int(os.getenv("OTP_MIN", "4")), int(os.getenv("OTP_MAX", "8"))
WINDOW_NEAR          = int(os.getenv("WINDOW_NEAR", "300"))          # 近邻窗口（前后各这么多字符）
ALLOW_CODE_IN_URL    = os.getenv("ALLOW_CODE_IN_URL", "0") == "1"    # 允许链接/邮箱里的数字
LOOSE_MODE           = os.getenv("LOOSE_MODE", "0") == "1"           # 宽松模式（见 extract_code 说明）

# 关键词（可用 NEAR_KEYS_EXTRA=英文,中文,passcode 追加）
NEAR_KEYS_BASE = ["验证码","校验码","code","verify","verification","登录","安全","2FA","OTP",
                  "PIN","passcode","your code","one-time password","magic code","提取码","口令",
                  "auth","authentication code"]
NEAR_KEYS_EXTRA = [s.strip() for s in os.getenv("NEAR_KEYS_EXTRA","").split(",") if s.strip()]
NEAR_KEYS = NEAR_KEYS_BASE + NEAR_KEYS_EXTRA

# 文本间隔（大间隔：EM 空格 U+2003），复制时也保留空格
EMSP = "\u2003"
GAP = EMSP * 6
# =======================================================================

CODE_RE = re.compile(r"(?<!\d)(?:\d[\s-]?){%d,%d}(?!\d)" % (OTP_MIN, OTP_MAX))

def dec(s):
    if not s: return ""
    try:
        return str(make_header(decode_header(s)))
    except Exception:
        return s or ""

def body_text(msg):
    """抽取 text/plain，退化到 text/html 转纯文本；失败返回空串"""
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

# ========== 改动重点部分：时间保持原样（不再加本地时区） ==========
def mail_time_str(msg):
    """保持邮件原始时区：MM-DD HH:MM"""
    try:
        raw = msg.get("Date")
        if raw:
            dt = parsedate_to_datetime(raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            local_dt = dt
        else:
            local_dt = datetime.now()
        return local_dt.strftime("%m-%d %H:%M")
    except Exception:
        return datetime.now().strftime("%m-%d %H:%M")

def mail_time_str_ymd(msg):
    """保持邮件原始时区：YYYY年MM月DD日 HH:MM"""
    try:
        raw = msg.get("Date")
        if raw:
            dt = parsedate_to_datetime(raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            local_dt = dt
        else:
            local_dt = datetime.now()
        return local_dt.strftime("%Y年%m月%d日 %H:%M")
    except Exception:
        return datetime.now().strftime("%Y年%m月%d日 %H:%M")
# ===============================================================

def send_tg(token, chat_id, text, proxy=None):
    """Telegram 推送"""
    if not token or not chat_id or not text:
        return
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    proxies = {"http":proxy,"https":proxy} if proxy else None
    try:
        requests.post(url, data={"chat_id":chat_id,"text":text}, timeout=10, proxies=proxies)
    except Exception as e:
        print("Telegram 推送失败：", e)

def connect_pop3(host, user, pwd, port_ssl=995, port_plain=110):
    """优先 995/SSL；失败回落 110(+STLS)/明文"""
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
    """返回 {序号: UIDL}；失败返回 {}"""
    try:
        resp, lst, _ = srv.uidl(); m={}
        for line in lst or []:
            parts = line.decode("utf-8","ignore").split()
            if len(parts)>=2: m[int(parts[0])] = parts[1]
        return m
    except Exception:
        return {}

def fetch_msg(srv, num):
    """拉取一封并解析为 email.message.Message"""
    resp, lines, _ = srv.retr(num)
    raw = b"\r\n".join(lines)
    return email.message_from_bytes(raw)

_URL_RE   = re.compile(r'https?://[^\s<>"]+')
_EMAIL_RE = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')

def _overlaps(a_start, a_end, b_start, b_end):
    return not (a_end <= b_start or b_end <= a_start)

def _slice_window(text, s, e, extra=120):
    lo = max(0, s - extra)
    hi = min(len(text), e + extra)
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

def _has_any_key(text):
    low = (text or "").lower()
    return any(k.lower() in low for k in NEAR_KEYS)

def extract_code(text: str, subject: str = ""):
    subj = subject or ""
    body = text or ""
    hay  = subj + "\n" + body

    candidates = []
    for m in CODE_RE.finditer(hay):
        s, e  = m.span()
        lo    = max(0, s - WINDOW_NEAR)
        hi    = min(len(hay), e + WINDOW_NEAR)
        near  = hay[lo:hi].lower()
        if any(k.lower() in near for k in NEAR_KEYS):
            if not ALLOW_CODE_IN_URL and _in_url_or_email(hay, s, e):
                continue
            candidates.append(m.group())

    if candidates:
        return re.sub(r"[\s-]", "", candidates[0])

    if LOOSE_MODE or _has_any_key(hay):
        for m in CODE_RE.finditer(hay):
            s, e = m.span()
            if not ALLOW_CODE_IN_URL and _in_url_or_email(hay, s, e):
                continue
            return re.sub(r"[\s-]", "", m.group())

    return None

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
                    text  = body_text(msg)
                    code  = extract_code(text, subj)
                    if code:
                        ts   = mail_time_str_ymd(msg)
                        frm  = dec(msg.get("From")) or "(unknown)"
                        to   = dec(msg.get("To")) or user
                        send_meta_then_code(token, chat, frm, to, ts, code, proxy)
                        with open("latest_code.txt","w",encoding="utf-8") as f: f.write(code)
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
                        text  = body_text(msg)
                        code  = extract_code(text, subj)
                        if code:
                            ts   = mail_time_str_ymd(msg)
                            frm  = dec(msg.get("From")) or "(unknown)"
                            to   = dec(msg.get("To")) or user
                            send_meta_then_code(token, chat, frm, to, ts, code, proxy)
                            with open("latest_code.txt","w",encoding="utf-8") as f: f.write(code)
                    except Exception as e:
                        print("历史邮件处理失败：", e)
                with open(flag, "w") as f: f.write("done")
            baseline_total = total

    if m0:
        seen_uids.update(m0.values())

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
                text = body_text(msg)
                code = extract_code(text, subj)
                if code:
                    ts   = mail_time_str_ymd(msg)
                    frm  = dec(msg.get("From")) or "(unknown)"
                    to   = dec(msg.get("To")) or user
                    send_meta_then_code(token, chat, frm, to, ts, code, proxy)
                    with open("latest_code.txt","w",encoding="utf-8") as f: f.write(code)

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
        send_tg(token, chat,
                "✅ POP3 验证码监听已启动。（现在时间显示为邮件原始时区）",
                proxy)
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
