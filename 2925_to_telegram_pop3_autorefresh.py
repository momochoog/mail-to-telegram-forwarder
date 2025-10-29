#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
改动要点：
- OTP_MIN/OTP_MAX 固定 6 位
- WINDOW_NEAR 扩大到 180
- extract_code() 加入“宽松模式”兜底（RELAXED_OTP=1 时，转发任意 6 位数字，仍规避 URL/邮箱）
"""

import os, re, time, ssl, poplib, email, requests, hashlib
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from email.header import decode_header, make_header
from email.utils import parsedate_to_datetime, parseaddr
from datetime import datetime

# ====== 可调参数 ======
FETCH_STARTUP_LAST_N = 2     # 启动时最多读取 N 条历史验证码（仅一次）
POLL_SECONDS = 1             # 轮询间隔（秒）
RECONNECT_EVERY = 10         # 每隔 X 秒强制重连（更快看到新邮件）
OTP_MIN, OTP_MAX = 5, 8      # 验证码长度范围（固定 6 位）
WINDOW_NEAR = 180            # 关键字近邻窗口（字符）

# Telegram 发送优化
PER_CHAT_GAP = 0.8
TG_CONNECT_TIMEOUT = 3
TG_READ_TIMEOUT = 5
TG_RETRIES = 2
# =====================

NEAR_KEYS = [
    "验证码","校验码","确认码","动态码","一次性","短信码","安全码","登录码",
    "登录","验证","认证","绑定","注册","激活","重置","找回","支付","提现","取款",
    "otp","2fa","code","passcode","security code","verification code",
    "verify","verification","login","sign-in","signin","one-time code","two-factor",
    # 新增一些常见提示词
    "authentication","auth code","确认登录","安全验证","动态密码","一次性密码","登录确认","登录验证"
]

# 统一长度（与 OTP_MIN/OTP_MAX 一致）；允许中间空格/横杠
CODE_RE = re.compile(r"(?<![A-Za-z0-9])(?:\d[ \t-]?){%d,%d}(?![A-Za-z0-9])" % (OTP_MIN, OTP_MAX))

# ---- Telegram 会话：连接复用 + 自动重试 ----
TG_SESSION = requests.Session()
_adapter = HTTPAdapter(
    pool_connections=4,
    pool_maxsize=8,
    max_retries=Retry(
        total=TG_RETRIES,
        backoff_factor=0.3,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=frozenset(["POST"])
    )
)
TG_SESSION.mount("https://", _adapter)
TG_SESSION.mount("http://", _adapter)

DEBUG = os.getenv("DEBUG", "0") == "1"

def dprint(*args):
    if DEBUG:
        print(*args, flush=True)

def dec(s):
    if not s: return ""
    try: return str(make_header(decode_header(s)))
    except Exception: return s

def body_text(msg):
    if msg.is_multipart():
        # 优先 text/plain
        for p in msg.walk():
            if p.get_content_type()=="text/plain" and "attachment" not in str(p.get("Content-Disposition") or ""):
                try:
                    return p.get_payload(decode=True).decode(p.get_content_charset() or "utf-8","ignore")
                except Exception:
                    pass
        # 次选 text/html -> 纯文本
        for p in msg.walk():
            if p.get_content_type()=="text/html":
                from html import unescape
                try:
                    h = p.get_payload(decode=True).decode(p.get_content_charset() or "utf-8","ignore")
                except Exception:
                    h = ""
                h = re.sub(r"<(script|style)[\s\S]*?</\1>", " ", h, flags=re.I)
                return re.sub(r"\s+"," ", re.sub(r"<[^>]+>"," ", unescape(h)))
    else:
        try: return msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8","ignore")
        except Exception: return ""
    return ""

def mail_time_str_full(msg):
    try:
        raw = msg.get("Date")
        if raw:
            dt = parsedate_to_datetime(raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
            local_dt = dt.astimezone(datetime.now().astimezone().tzinfo)
        else:
            local_dt = datetime.now().astimezone()
        return local_dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")

def send_tg(token, chat_id, text, proxy=None):
    """ 发送 Telegram 文本消息；若遇 429，读取 retry_after 并等待重试一次。 """
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    proxies = {"http":proxy,"https":proxy} if proxy else None
    try:
        r = TG_SESSION.post(
            url,
            data={"chat_id":chat_id,"text":text},
            timeout=(TG_CONNECT_TIMEOUT, TG_READ_TIMEOUT),
            proxies=proxies
        )
        if r.status_code == 429:
            try:
                ra = int(r.json().get("parameters", {}).get("retry_after", 1))
            except Exception:
                ra = 1
            time.sleep(ra + 0.2)
            TG_SESSION.post(url, data={"chat_id":chat_id,"text":text},
                            timeout=(TG_CONNECT_TIMEOUT, TG_READ_TIMEOUT),
                            proxies=proxies)
    except Exception as e:
        print("Telegram 推送失败：", e, flush=True)

def connect_pop3(host, user, pwd, port_ssl=995, port_plain=110):
    try:
        ctx = ssl.create_default_context()
        srv = poplib.POP3_SSL(host, port_ssl, context=ctx, timeout=10)
        srv.user(user); srv.pass_(pwd)
        print("[POP3] 995/SSL", flush=True)
        return srv
    except Exception as e:
        print("[POP3] 995 失败，用 110+STLS/PLAIN：", e, flush=True)
        srv = poplib.POP3(host, port_plain, timeout=10)
        try:
            srv.stls(); print("[POP3] 110 已升级 STLS", flush=True)
        except Exception:
            print("[POP3] 110 明文（仅在可信网络用）", flush=True)
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

def _has_near_key(s: str) -> bool:
    s = (s or "").lower()
    return any(k.lower() in s for k in NEAR_KEYS)

def _in_url_or_email(hay: str, s: int, e: int) -> bool:
    """更稳妥的 URL/邮箱附近过滤"""
    before = hay[max(0, s-120):s]
    after  = hay[e:e+120]
    b = before.rstrip().lower()
    a = after.lstrip().lower()

    # 邮箱地址中的数字
    if b.endswith('@') or ('@' in b and not b.endswith(' ')): 
        return True
    if a.startswith('.') and re.match(r"\.[a-z]{2,10}\b", a): 
        return True

    # URL 附近（考虑长 query/fragment）
    near = hay[max(0, s-150):e+150].lower()
    if "http://" in near or "https://" in near or "://" in near:
        return True
    # 典型 URL 连接符号
    if re.search(r"[?&=#/_-]{0,30}$", b) or re.match(r"^[?&=#/_-]", a):
        return True
    return False

def extract_code(text: str, subject: str = ""):
    """
    仅在“附近窗口命中关键词”或“主题命中关键词”时返回验证码；
    若未命中且开启 RELAXED_OTP=1，则宽松匹配任意 6 位数字（避开 URL/邮箱）。
    """
    hay = ((subject or "") + "\n" + (text or ""))
    candidates = []

    for m in CODE_RE.finditer(hay):
        digits = re.sub(r"\D", "", m.group())
        if not (OTP_MIN <= len(digits) <= OTP_MAX):
            continue
        s, e = m.span()
        if _in_url_or_email(hay, s, e):
            continue

        win = hay[max(0, s - WINDOW_NEAR): min(len(hay), e + WINDOW_NEAR)]
        near_hit = _has_near_key(win)
        subj_hit = _has_near_key(subject)

        # 只有命中关键词才纳入候选
        if near_hit or subj_hit:
            score = 0 if near_hit else 1  # 0=附近命中，1=仅主题命中
            candidates.append((score, s, digits))

    if not candidates:
        # 宽松模式兜底
        if os.getenv("RELAXED_OTP", "0") == "1":
            m2 = re.search(r"(?<!\d)\d{6}(?!\d)", hay)
            if m2:
                s2, e2 = m2.span()
                if not _in_url_or_email(hay, s2, e2):
                    dprint("[RELAXED] 命中 6 位数字")
                    return m2.group()
        return None

    candidates.sort(key=lambda x: (x[0], x[1]))  # 附近命中优先；相同按出现顺序
    return candidates[0][2]

def startup_flag_path(user):
    key = hashlib.sha1(user.encode("utf-8")).hexdigest()[:12]
    return os.path.join(os.getcwd(), f".startup_done_{key}.flag")

def sender_str(msg):
    frm = msg.get("From") or ""
    name, addr = parseaddr(frm)
    name = dec(name)
    if name and addr: return f"{name} <{addr}>"
    return addr or name or "(未知发件人)"

def send_time_and_code(token, chat, code, ts_full, sender, proxy=None):
    prefix = f"📬 邮箱收到 | {ts_full} | 发件人：{sender}"
    send_tg(token, chat, prefix, proxy)
    time.sleep(PER_CHAT_GAP)
    send_tg(token, chat, code, proxy)

def run_session(host, user, pwd, token, chat, proxy, seen_uids):
    srv = connect_pop3(host, user, pwd,
                       int(os.getenv("POP3_PORT_SSL","995")),
                       int(os.getenv("POP3_PORT_PLAIN","110")))
    total, _ = srv.stat()

    # ---- 启动阶段：读取最近 N 封（去重）----
    m0 = uidl_map(srv)
    baseline_total = None
    if FETCH_STARTUP_LAST_N > 0 and total > 0:
        start = max(1, total - FETCH_STARTUP_LAST_N + 1)
        if m0:
            for num in range(start, total+1):
                uid = m0.get(num)
                if not uid or uid in seen_uids: continue
                try:
                    msg  = fetch_msg(srv, num)
                    subj = dec(msg.get("Subject"))
                    text = body_text(msg)
                    code = extract_code(text or "", subj)
                    if code:
                        tsf = mail_time_str_full(msg)
                        sender = sender_str(msg)
                        send_time_and_code(token, chat, code, tsf, sender, proxy)
                        try: open("latest_code.txt","w",encoding="utf-8").write(code)
                        except Exception: pass
                    seen_uids.add(uid)
                except Exception as e:
                    print("历史邮件处理失败：", e, flush=True)
        else:
            flag = startup_flag_path(user)
            if not os.path.exists(flag):
                for num in range(start, total+1):
                    try:
                        msg  = fetch_msg(srv, num)
                        subj = dec(msg.get("Subject"))
                        text = body_text(msg)
                        code = extract_code(text or "", subj)
                        if code:
                            tsf = mail_time_str_full(msg)
                            sender = sender_str(msg)
                            send_time_and_code(token, chat, code, tsf, sender, proxy)
                            try: open("latest_code.txt","w",encoding="utf-8").write(code)
                            except Exception: pass
                    except Exception as e:
                        print("历史邮件处理失败：", e, flush=True)
                try: open(flag, "w").write("done")
                except Exception: pass
            baseline_total = total
    # --------------------------------------

    if m0:
        seen_uids.update(m0.values())

    # ========== 轮询阶段：UIDL+STAT 双检测 ==========
    t0 = time.time()
    seen_nums = set()
    last_stat_total = total

    while True:
        if time.time() - t0 >= RECONNECT_EVERY:
            break
        try:
            m = uidl_map(srv)            # 1) UIDL
            cur_total, _ = srv.stat()    # 2) STAT

            new_by_uidl, new_by_stat = [], []
            if m:
                for n,u in sorted(m.items()):
                    if u not in seen_uids and n not in seen_nums:
                        new_by_uidl.append(n)

            if cur_total > (last_stat_total or 0):
                for n in range((last_stat_total or 0)+1, cur_total+1):
                    if n not in seen_nums:
                        new_by_stat.append(n)
            last_stat_total = cur_total

            if not m:
                if baseline_total is None:
                    baseline_total = cur_total
                new_by_stat = [n for n in range(baseline_total+1, cur_total+1) if n not in seen_nums]
                baseline_total = cur_total

            new_nums = sorted(set(new_by_uidl) | set(new_by_stat))[-20:]

            for num in new_nums:
                msg  = fetch_msg(srv, num)
                subj = dec(msg.get("Subject"))
                text = body_text(msg)
                code = extract_code(text or "", subj)
                if code:
                    tsf = mail_time_str_full(msg)
                    sender = sender_str(msg)
                    send_time_and_code(token, chat, code, tsf, sender, proxy)
                    try: open("latest_code.txt","w",encoding="utf-8").write(code)
                    except Exception: pass

                if m:
                    uid = m.get(num)
                    if uid: seen_uids.add(uid)
                seen_nums.add(num)

            time.sleep(POLL_SECONDS)

        except poplib.error_proto as e:
            print("[POP3] 会话异常，切换到重连…", e, flush=True); break
        except Exception as e:
            print("错误：", e, flush=True); time.sleep(POLL_SECONDS)
    # ================================================

    try: srv.quit()
    except Exception: pass

def main():
    try:
        from dotenv import load_dotenv; load_dotenv()
    except Exception:
        pass

    host  = os.getenv("POP3_HOST","pop.2925.com").strip()
    user  = os.getenv("EMAIL_USER","")
    pwd   = os.getenv("EMAIL_PASS","")
    token = os.getenv("TELEGRAM_BOT_TOKEN","")
    chat  = os.getenv("TELEGRAM_CHAT_ID","")
    proxy = os.getenv("TG_PROXY") or None

    try:
        send_tg(token, chat, "✅ POP3 验证码监听已启动。（宽松模式可用：RELAXED_OTP=1）", proxy)
    except Exception as e:
        print("❌ Telegram 失败：", e, flush=True)

    seen_uids = set()
    while True:
        try:
            run_session(host, user, pwd, token, chat, proxy, seen_uids)
        except KeyboardInterrupt:
            print("\n已退出。", flush=True); break
        except Exception as e:
            print("重连失败：", e, flush=True)
        time.sleep(1)

if __name__ == "__main__":
    main()
