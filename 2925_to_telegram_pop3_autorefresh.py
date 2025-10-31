#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
可选环境变量（不设也能用）：
# —— 时间相关（默认=按邮箱收到时间显示为北京时间）——
TIME_SOURCE=received          # received | date  （优先顶层 Received；收不到就用 Date）
TIME_TZ=Asia/Shanghai         # 目标显示时区
TIME_CONVERT=1                # 1=把邮件头时间换算到目标时区；0=不换算
TIME_FMT=%Y年%m月%d日 %H:%M     # 显示格式

# —— 验证码识别（更严格防误报）——
OTP_MIN=6                     # 最小位数（默认6）
OTP_MAX=8                     # 最大位数
WINDOW_NEAR=120               # 关键词近邻窗口大小（字符数）
ALLOW_CODE_IN_URL=0           # 是否允许落在 URL/邮箱中的数字
NEAR_KEYS_EXTRA=              # 追加正向关键词，逗号分隔
NEG_KEYS_EXTRA=               # 追加负向关键词，逗号分隔
"""

import os, re, time, ssl, poplib, email, requests, hashlib
from email.header import decode_header, make_header
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone, timedelta

# ====== 运行参数 ======
FETCH_STARTUP_LAST_N = int(os.getenv("FETCH_STARTUP_LAST_N", "2"))   # 启动最多补扫 N 条（仅一次）
POLL_SECONDS         = float(os.getenv("POLL_SECONDS", "2"))         # 轮询间隔（秒）
RECONNECT_EVERY      = float(os.getenv("RECONNECT_EVERY", "10"))     # 每 N 秒强制重连
# 文本大间隔（EM 空格，复制时保留）
EMSP = "\u2003"
GAP  = EMSP * 6

# ====== 时间显示配置（默认：按邮箱收到时间，显示为北京时间） ======
TIME_SOURCE  = os.getenv("TIME_SOURCE", "received").lower()   # 'received' | 'date'
TIME_CONVERT = os.getenv("TIME_CONVERT", "1") == "1"
TIME_FMT     = os.getenv("TIME_FMT", "%Y年%m月%d日 %H:%M")
try:
    from zoneinfo import ZoneInfo
    TARGET_TZ = ZoneInfo(os.getenv("TIME_TZ", "Asia/Shanghai"))
except Exception:
    TARGET_TZ = timezone(timedelta(hours=8))  # 兜底：东八区

# ====== 验证码识别配置（严格防误报） ======
OTP_MIN  = int(os.getenv("OTP_MIN",  "6"))
OTP_MAX  = int(os.getenv("OTP_MAX",  "8"))
WINDOW_NEAR = int(os.getenv("WINDOW_NEAR", "120"))
ALLOW_CODE_IN_URL = os.getenv("ALLOW_CODE_IN_URL","0") == "1"

NEAR_KEYS_BASE = [
    "验证码","校验码","动态码","口令","一次性",
    "verify","verification","verification code","auth","authentication",
    "otp","one-time","passcode","security code","2fa","login code"
]
NEAR_KEYS_EXTRA = [s.strip() for s in os.getenv("NEAR_KEYS_EXTRA","").split(",") if s.strip()]
NEAR_KEYS = [k.lower() for k in (NEAR_KEYS_BASE + NEAR_KEYS_EXTRA)]

NEG_KEYS_BASE = [
    "账单","发票","订单","收据","套餐","订阅","价格","金额","扣费","退款",
    "invoice","receipt","order","subscription","plan","billing","amount","price",
    "usd","$","合计","税额","折扣","seat","business"
]
NEG_KEYS_EXTRA = [s.strip() for s in os.getenv("NEG_KEYS_EXTRA","").split(",") if s.strip()]
NEG_KEYS = [k.lower() for k in (NEG_KEYS_BASE + NEG_KEYS_EXTRA)]

CODE_RE = re.compile(r"(?<!\d)(?:\d[\s-]?){%d,%d}(?!\d)" % (OTP_MIN, OTP_MAX))
_URL_RE   = re.compile(r'https?://[^\s<>"]+')
_EMAIL_RE = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')

# ====== 工具函数 ======
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

# —— 时间解析：优先顶层 Received（越靠上越新），否则 Date
def _parse_received_dt(msg):
    try:
        recvs = msg.get_all('Received') or []
        for r in recvs:
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
    if not isinstance(dt, datetime):
        return None
    if TIME_CONVERT:
        if dt.tzinfo is None:
            return dt.replace(tzinfo=TARGET_TZ)  # 无时区 → 视作目标时区
        return dt.astimezone(TARGET_TZ)
    else:
        return dt  # 不换算

def mail_time_str_ymd(msg):
    if TIME_SOURCE == "received":
        dt = _parse_received_dt(msg) or _parse_date_dt(msg)
    else:
        dt = _parse_date_dt(msg) or _parse_received_dt(msg)

    if dt is None:
        dt = datetime.now(TARGET_TZ) if TIME_CONVERT else datetime.now()

    dt2 = _to_target_tz(dt) or dt
    return dt2.strftime(TIME_FMT)

# —— Telegram 发送
def send_tg(token, chat_id, text, proxy=None):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    proxies = {"http":proxy,"https":proxy} if proxy else None
    try:
        requests.post(url, data={"chat_id":chat_id,"text":text}, timeout=10, proxies=proxies)
    except Exception as e:
        print("Telegram 推送失败：", e)

# —— POP3 连接
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

# —— 验证码提取（严格防误报）
def _overlaps(a0, a1, b0, b1): return not (a1 <= b0 or b1 <= a0)
def _slice(text, s, e, extra): lo=max(0, s-extra); hi=min(len(text), e+extra); return text[lo:hi], lo, hi

def _in_url_or_email(hay, s, e):
    win, base, _ = _slice(hay, s, e, extra=200)
    for m in _URL_RE.finditer(win):
        if _overlaps(s, e, base+m.start(), base+m.end()): return True
    for m in _EMAIL_RE.finditer(win):
        if _overlaps(s, e, base+m.start(), base+m.end()): return True
    return False

def extract_code(body_text_str: str, subject: str = "", from_str: str = "") -> str | None:
    subj = subject or ""
    body = body_text_str or ""
    hay  = subj + "\n" + body

    for m in CODE_RE.finditer(hay):
        s, e = m.span()

        # 默认不允许在链接/邮箱里的数字
        if not ALLOW_CODE_IN_URL and _in_url_or_email(hay, s, e):
            continue

        win, _, _ = _slice(hay, s, e, extra=WINDOW_NEAR)
        wlow = win.lower()

        has_pos = any(k in wlow for k in NEAR_KEYS)
        has_neg = any(k in wlow for k in NEG_KEYS)

        # 必须命中正向关键词；账单类数字被负面词命中时直接忽略
        if not has_pos:
            continue
        if has_neg and not has_pos:
            continue

        return re.sub(r"[\s-]", "", m.group())

    return None

# —— 启动去重 Flag（无 UIDL 时）
def startup_flag_path(user):
    key = hashlib.sha1(user.encode("utf-8")).hexdigest()[:12]
    return os.path.join(os.getcwd(), f".startup_done_{key}.flag")

# —— 两条消息：第一条元信息，第二条纯验证码
def send_meta_then_code(token, chat, frm, to, ts, code, proxy=None):
    meta = f"📬 {ts}{GAP}{frm} → {to}"
    send_tg(token, chat, meta, proxy)
    send_tg(token, chat, code, proxy)

# ====== 主循环 ======
def run_session(host, user, pwd, token, chat, proxy, seen_uids):
    srv = connect_pop3(host, user, pwd,
                       int(os.getenv("POP3_PORT_SSL","995")),
                       int(os.getenv("POP3_PORT_PLAIN","110")))
    total, _ = srv.stat()

    m0 = uidl_map(srv)
    baseline_total = None

    # —— 启动阶段（可补扫最近 N 封）
    if FETCH_STARTUP_LAST_N > 0 and total > 0:
        start = max(1, total - FETCH_STARTUP_LAST_N + 1)
        if m0:
            for num in range(start, total+1):
                uid = m0.get(num)
                if not uid or uid in seen_uids: continue
                try:
                    msg  = fetch_msg(srv, num)
                    subj = dec(msg.get("Subject"))
                    frm  = dec(msg.get("From") or "")
                    to   = dec(msg.get("To") or user)
                    text = body_text(msg)
                    code = extract_code(text, subj, frm)
                    if code:
                        ts = mail_time_str_ymd(msg)
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
                        subj = dec(msg.get("Subject"))
                        frm  = dec(msg.get("From") or "")
                        to   = dec(msg.get("To") or user)
                        text = body_text(msg)
                        code = extract_code(text, subj, frm)
                        if code:
                            ts = mail_time_str_ymd(msg)
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

    if m0:
        seen_uids.update(m0.values())

    # —— 轮询新邮件
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
                if baseline_total is None: baseline_total = cur_total
                new_nums = list(range(baseline_total+1, cur_total+1))
                baseline_total = cur_total

            for num in new_nums[-20:]:
                msg  = fetch_msg(srv, num)
                subj = dec(msg.get("Subject"))
                frm  = dec(msg.get("From") or "")
                to   = dec(msg.get("To") or user)
                text = body_text(msg)
                code = extract_code(text, subj, frm)
                if code:
                    ts = mail_time_str_ymd(msg)
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

    try:
        srv.quit()
    except Exception:
        pass

def main():
    # .env
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

    try:
        send_tg(token, chat, "✅ POP3 验证码监听已启动。（开机最多读 2 条历史；按邮箱收到时间显示）", proxy)
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
