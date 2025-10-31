#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, re, time, ssl, poplib, email, requests, hashlib
from email.header import decode_header, make_header
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone

# 提前加载 .env，便于 os.getenv 生效
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ===================== 可调参数（均可用环境变量覆盖） =====================
FETCH_STARTUP_LAST_N = int(os.getenv("FETCH_STARTUP_LAST_N", "2"))   # 启动最多补扫 N 封（仅一次）
POLL_SECONDS         = float(os.getenv("POLL_SECONDS", "2"))         # 轮询间隔（秒）
RECONNECT_EVERY      = float(os.getenv("RECONNECT_EVERY", "10"))     # 每隔 N 秒强制重连
DEDUP_SEC            = int(os.getenv("DEDUP_SEC", "20"))             # 相同验证码去重时间窗（秒）

# 识别相关
OTP_MIN, OTP_MAX     = int(os.getenv("OTP_MIN", "4")), int(os.getenv("OTP_MAX", "8"))
WINDOW_NEAR          = int(os.getenv("WINDOW_NEAR", "300"))          # 近邻窗口
ALLOW_CODE_IN_URL    = os.getenv("ALLOW_CODE_IN_URL", "0") == "1"    # 是否允许链接/邮箱里的数字（一般 0）
LOOSE_MODE           = os.getenv("LOOSE_MODE", "0") == "1"           # 宽松模式（不建议常开）
DEBUG_LOG            = os.getenv("DEBUG_LOG", "0") == "1"            # 调试日志（可临时开）

# 关键词（可用 NEAR_KEYS_EXTRA=英文,中文,passcode 追加）
NEAR_KEYS_BASE = ["验证码","代码","校验码","code","verify","verification",
                  "登录","安全","2FA","OTP","PIN","passcode","your code",
                  "one-time password","magic code","提取码","口令","auth",
                  "authentication code"]
NEAR_KEYS_EXTRA = [s.strip() for s in os.getenv("NEAR_KEYS_EXTRA","").split(",") if s.strip()]
NEAR_KEYS = NEAR_KEYS_BASE + NEAR_KEYS_EXTRA

# 文本间隔（EM 空格 U+2003），复制时也保留空格
EMSP = "\u2003"
GAP = EMSP * 6

# 正则
CODE_RE = re.compile(r"(?<!\d)(?:\d[\s-]?){%d,%d}(?!\d)" % (OTP_MIN, OTP_MAX))
URL_RE   = re.compile(r'https?://[^\s<>"]+')
EMAIL_RE = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')

# 近况去重：同一发件人->收件人下最近一次验证码
_recent_sent = {}  # key=(frm,to), val=(code, ts)

# =======================================================================

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

# ==================== 时间：严格用邮件原始时间，不做本地换算 ====================
def mail_time_str(msg):
    """保持邮件原始时区：MM-DD HH:MM"""
    try:
        raw = msg.get("Date")
        if raw:
            dt = parsedate_to_datetime(raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)  # 无时区按 UTC 处理
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

# =======================================================================

def send_tg(token, chat_id, text, proxy=None):
    if not token or not chat_id or not text:
        return
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

# ================ URL/邮箱位置识别（用于过滤链接或邮箱里的数字） =================
def _overlaps(a_start, a_end, b_start, b_end):
    return not (a_end <= b_start or b_end <= a_start)

def _slice_window(text, s, e, extra=120):
    lo = max(0, s - extra); hi = min(len(text), e + extra)
    return text[lo:hi], lo, hi

def _in_url_or_email(hay, s, e):
    """判断 [s,e) 这段数字是否处在 URL/邮箱里（或紧邻）"""
    win, base, _ = _slice_window(hay, s, e, extra=200)
    for m in URL_RE.finditer(win):
        if _overlaps(s, e, base+m.start(), base+m.end()):
            return True
    for m in EMAIL_RE.finditer(win):
        if _overlaps(s, e, base+m.start(), base+m.end()):
            return True
    return False

def _has_any_key(text):
    low = (text or "").lower()
    return any(k.lower() in low for k in NEAR_KEYS)

# ======================= 更稳的验证码提取策略 ============================
def extract_code(text: str, subject: str = "", frm: str = ""):
    """
    A) 主题优先：主题里 4–8 位（OpenAI 强制 6 位）
    B) 正文同一行含关键词的数字优先（先行后文），并避开 URL/邮箱数字
    C) 再按“数字与任一关键词的最小距离”选取（仍避开 URL/邮箱）
    D) OpenAI 特判：只取 6 位（含更强的专用正则）
    """
    subj = (subject or "")
    body = (text or "")
    hay  = subj + "\n" + body

    def _is_openai():
        src = (subj + " " + (frm or "")).lower()
        return "openai.com" in src or "chatgpt" in src

    def _digits_iter(s):
        return list(CODE_RE.finditer(s or ""))

    # -------- D0) OpenAI 强模板（优先于一切，如果命中）--------
    if _is_openai():
        # 中英文常见模板："...ChatGPT 代码为 123456" / "verification code is 123456"
        pat_list = [
            r"(?:chatgpt|openai).{0,20}?(?:验证码|代码|code|verification).{0,10}?(\d{6})",
            r"(?:verification\s*code|your\s*code).{0,10}?(\d{6})",
            r"(?:请输入|使用).{0,20}?(\d{6}).{0,10}?(?:验证码|code)"
        ]
        for pat in pat_list:
            m = re.search(pat, hay, re.IGNORECASE | re.DOTALL)
            if m:
                g = m.group(1)
                if DEBUG_LOG: print("[extract] OpenAI strong pattern ->", g)
                return g

    # -------- A) 主题优先 --------
    subj_nums = _digits_iter(subj)
    if subj_nums:
        for m in subj_nums:
            g = re.sub(r"[\s-]", "", m.group())
            if _is_openai() and len(g) != 6:
                continue
            if DEBUG_LOG: print("[extract] from subject ->", g)
            return g

    # -------- B) 正文“同一行 + 关键词”优先 --------
    lines = body.splitlines()
    offset = 0  # 当前行在 body 中的起始全局下标
    for ln in lines:
        lnl = ln.lower()
        if any(k.lower() in lnl for k in NEAR_KEYS):
            for m in _digits_iter(ln):
                s_local, e_local = m.span()
                s_glob, e_glob   = offset + s_local, offset + e_local
                g = re.sub(r"[\s-]", "", m.group())
                if _is_openai() and len(g) != 6:
                    continue
                if (("http" in lnl or "@" in lnl) and (not ALLOW_CODE_IN_URL)
                        and _in_url_or_email(body, s_glob, e_glob)):
                    continue
                if DEBUG_LOG: print("[extract] same-line+key ->", g)
                return g
        offset += len(ln) + 1  # +1 为换行

    # -------- C) 全局：与关键词距离最近 --------
    key_pos = []
    low_hay = hay.lower()
    for kw in NEAR_KEYS:
        p = 0; kwl = kw.lower()
        while True:
            idx = low_hay.find(kwl, p)
            if idx == -1: break
            key_pos.append(idx); p = idx + len(kwl)
    key_pos = sorted(set(key_pos))

    best = None  # (dist, digits)
    if key_pos:
        for m in CODE_RE.finditer(hay):
            s, e = m.span()
            if not ALLOW_CODE_IN_URL and _in_url_or_email(hay, s, e):
                continue
            g = re.sub(r"[\s-]", "", m.group())
            if _is_openai() and len(g) != 6:
                continue
            d = min(abs(s - kp) for kp in key_pos)
            if (best is None) or (d < best[0]):
                best = (d, g)
    if best:
        if DEBUG_LOG: print("[extract] nearest-key ->", best[1])
        return best[1]

    # -------- D) OpenAI 兜底：只取 6 位 --------
    if _is_openai():
        for m in CODE_RE.finditer(hay):
            s, e = m.span()
            if not ALLOW_CODE_IN_URL and _in_url_or_email(hay, s, e):
                continue
            g = re.sub(r"[\s-]", "", m.group())
            if len(g) == 6:
                if DEBUG_LOG: print("[extract] openai fallback ->", g)
                return g

    # 不再使用“整封第一个数字”的不稳回退
    if DEBUG_LOG: print("[extract] no match")
    return None
# =======================================================================

def startup_flag_path(user):
    key = hashlib.sha1(user.encode("utf-8")).hexdigest()[:12]
    return os.path.join(os.getcwd(), f".startup_done_{key}.flag")

def _dedup(frm, to, code):
    """在 DEDUP_SEC 秒内，相同发件人->收件人的相同 code 不再重复推送"""
    now = time.time()
    k = (frm, to)
    last = _recent_sent.get(k)
    if last and last[0] == code and now - last[1] < DEDUP_SEC:
        return True
    _recent_sent[k] = (code, now)
    return False

def send_meta_then_code(token, chat, frm, to, ts, code, proxy=None):
    line1 = f"📬 {ts}  {frm} → {to}"
    send_tg(token, chat, line1, proxy)
    # 去重：同一对收发件人在时间窗内的相同 code 不重复发送第二条
    if not _dedup(frm, to, code):
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
                    frm   = dec(msg.get("From")) or ""
                    text  = body_text(msg)
                    code  = extract_code(text, subj, frm)
                    if code:
                        ts   = mail_time_str_ymd(msg)
                        to   = dec(msg.get("To")) or user
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
                        msg   = fetch_msg(srv, num)
                        subj  = dec(msg.get("Subject"))
                        frm   = dec(msg.get("From")) or ""
                        text  = body_text(msg)
                        code  = extract_code(text, subj, frm)
                        if code:
                            ts   = mail_time_str_ymd(msg)
                            to   = dec(msg.get("To")) or user
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
            "✅ POP3 验证码监听已启动。（两条消息；时间=邮件原始；OpenAI 6位；去重）",
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



