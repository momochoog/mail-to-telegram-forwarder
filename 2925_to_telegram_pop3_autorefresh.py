#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, re, time, ssl, poplib, email, requests, hashlib
from email.header import decode_header, make_header
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone, timedelta

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

# 识别相关（与“你本地成功版”保持一致，并加了 URL/邮箱过滤）
NEAR_KEYS = ["验证码","校验码","code","verify","verification","登录","安全","2FA","OTP"]
CODE_RE   = re.compile(r"(?<!\d)(?:\d[\s-]?){4,8}(?!\d)")

# 文本间隔（大间隔：EM 空格 U+2003），复制时也保留空格
EMSP = "\u2003"
GAP = EMSP * 6
# =======================================================================

# URL/邮箱识别（用于过滤链接或邮箱里的数字）
_URL_RE   = re.compile(r'https?://[^\s<>"]+')
_EMAIL_RE = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')

def _overlaps(a_start, a_end, b_start, b_end):
    return not (a_end <= b_start or b_end <= a_start)

def _slice_window(text, s, e, extra=120):
    lo = max(0, s - extra)
    hi = min(len(text), e + extra)
    return text[lo:hi], lo, hi

def _in_url_or_email(hay, s, e):
    """判断 [s,e) 这段数字是否处在 URL/邮箱里（或紧邻）"""
    win, base, _ = _slice_window(hay, s, e, extra=200)
    for m in _URL_RE.finditer(win):
        if _overlaps(s, e, base+m.start(), base+m.end()):
            return True
    for m in _EMAIL_RE.finditer(win):
        if _overlaps(s, e, base+m.start(), base+m.end()):
            return True
    return False

# ======================= 基础工具 ============================
def dec(s):
    if not s: return ""
    try:
        return str(make_header(decode_header(s)))
    except Exception:
        return s or ""

def body_text(msg):
    """抽取 text/plain；退化到 text/html 转纯文本；失败返回空串"""
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

# ==================== 时间显示规则 ====================
# 规则：优先使用邮件头 Date 的原始时区；若 Date 无时区（naive）或没有 Date，则按北京时间（Asia/Shanghai, +8）
def _bj_tz():
    # 无 tzdata 时退回固定 +8
    return timezone(timedelta(hours=8))

def _dt_from_mail(msg):
    raw = msg.get("Date")
    if not raw:
        return datetime.now(_bj_tz())
    dt = parsedate_to_datetime(raw)
    if dt.tzinfo is None:
        # 邮件没带时区 → 视为北京时间
        dt = dt.replace(tzinfo=_bj_tz())
    return dt

def mail_time_str(msg):
    try:
        return _dt_from_mail(msg).strftime("%m-%d %H:%M")
    except Exception:
        return datetime.now(_bj_tz()).strftime("%m-%d %H:%M")

def mail_time_str_ymd(msg):
    try:
        return _dt_from_mail(msg).strftime("%Y年%m月%d日 %H:%M")
    except Exception:
        return datetime.now(_bj_tz()).strftime("%Y年%m月%d日 %H:%M")

# ==================== TG 推送 ====================
def send_tg(token, chat_id, text, proxy=None):
    if not token or not chat_id or not text:
        return
    url = "https://api.telegram.org/bot{}/sendMessage".format(token)
    proxies = {"http":proxy,"https":proxy} if proxy else None
    try:
        requests.post(url, data={"chat_id":chat_id,"text":text}, timeout=10, proxies=proxies)
    except Exception as e:
        print("Telegram 推送失败：", e)

# ==================== POP3 连接 ====================
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

# ==================== 稳定提取验证码（正文-only） ====================
def extract_code(text: str):
    body = text or ""

    # 1) 先“同一行 + 关键词”
    # 为了能做 URL/邮箱过滤，需要把行定位回正文中的全局坐标
    base = 0
    for line in body.splitlines(True):  # 保留换行，便于累计 base
        pure_line = line.rstrip("\r\n")
        low = pure_line.lower()
        if any(k.lower() in low for k in NEAR_KEYS):
            m = CODE_RE.search(pure_line)
            if m:
                s_local, e_local = m.span()
                s_glob, e_glob = base + s_local, base + e_local
                if not _in_url_or_email(body, s_glob, e_glob):
                    return re.sub(r"[\s-]", "", m.group())
        base += len(line)

    # 2) 再“±30 窗口内有关键词”
    for mm in CODE_RE.finditer(body):
        s, e = mm.span()
        win = body[max(0, s-30):min(len(body), e+30)].lower()
        if any(k.lower() in win for k in NEAR_KEYS):
            if not _in_url_or_email(body, s, e):
                return re.sub(r"[\s-]", "", mm.group())

    # 3) 不再做“全局第一个数字”的危险兜底；找不到就返回 None
    return None

# ==================== 启动去重（无 UIDL 时） ====================
def startup_flag_path(user):
    key = hashlib.sha1(user.encode("utf-8")).hexdigest()[:12]
    return os.path.join(os.getcwd(), ".startup_done_{}.flag".format(key))

# ==================== 发送两条 ====================
def send_meta_then_code(token, chat, frm, to, ts, code, proxy=None):
    line1 = f"📬 {ts}  {frm} → {to}"
    send_tg(token, chat, line1, proxy)
    send_tg(token, chat, code, proxy)

# ==================== 主会话 ====================
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
            # 有 UIDL：逐封检查是否已处理过
            for num in range(start, total+1):
                uid = m0.get(num)
                if not uid or uid in seen_uids:
                    continue
                try:
                    msg   = fetch_msg(srv, num)
                    text  = body_text(msg)
                    code  = extract_code(text)
                    if code:
                        ts   = mail_time_str_ymd(msg)
                        frm  = dec(msg.get("From")) or "(unknown)"
                        to   = dec(msg.get("To")) or user
                        send_meta_then_code(token, chat, frm, to, ts, code, proxy)
                        try:
                            with open("latest_code.txt","w",encoding="utf-8") as f: f.write(code)
                        except Exception:
                            pass
                    seen_uids.add(uid)  # 标记已处理
                except Exception as e:
                    print("历史邮件处理失败：", e)
        else:
            # 无 UIDL：仅在第一次运行时推；之后靠 flag 防重复
            flag = startup_flag_path(user)
            if not os.path.exists(flag):
                for num in range(start, total+1):
                    try:
                        msg   = fetch_msg(srv, num)
                        text  = body_text(msg)
                        code  = extract_code(text)
                        if code:
                            ts   = mail_time_str_ymd(msg)
                            frm  = dec(msg.get("From")) or "(unknown)"
                            to   = dec(msg.get("To")) or user
                            send_meta_then_code(token, chat, frm, to, ts, code, proxy)
                            try:
                                with open("latest_code.txt","w",encoding="utf-8") as f: f.write(code)
                            except Exception:
                                pass
                    except Exception as e:
                        print("历史邮件处理失败：", e)
                # 写入 flag，后续重连不再重复推历史
                try:
                    with open(flag, "w") as f: f.write("done")
                except Exception:
                    pass
            # 无 UIDL：以当前总数为基线
            baseline_total = total
    # --------------------------------------------------------------------

    # 启动后：把当前信箱内所有 UID 标为已见，避免后续 while 又把历史识别为新
    if m0:
        seen_uids.update(m0.values())

    # ======================= 轮询阶段（只处理新邮件） ======================
    t0 = time.time()
    while True:
        if time.time() - t0 >= RECONNECT_EVERY:
            break  # 到点重连
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
                code = extract_code(text)
                if code:
                    ts   = mail_time_str_ymd(msg)
                    frm  = dec(msg.get("From")) or "(unknown)"
                    to   = dec(msg.get("To")) or user
                    send_meta_then_code(token, chat, frm, to, ts, code, proxy)
                    try:
                        with open("latest_code.txt","w",encoding="utf-8") as f: f.write(code)
                    except Exception:
                        pass

                uid = (m.get(num) if m else "no-uidl-{}".format(num))
                seen_uids.add(uid)  # 标记已处理，防重复

            time.sleep(POLL_SECONDS)

        except poplib.error_proto as e:
            print("[POP3] 会话异常，切换到重连…", e); break
        except Exception as e:
            print("错误：", e); time.sleep(POLL_SECONDS)
    # =====================================================================

    try: srv.quit()
    except Exception: pass

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
        send_tg(token, chat, "✅ POP3 验证码监听已启动。（启动补扫 2 封；时间=邮件原始/无则北京）", proxy)
    except Exception as e:
        print("❌ Telegram 失败：", e)

    seen_uids = set()  # 跨会话累积，防止重连后重复
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


