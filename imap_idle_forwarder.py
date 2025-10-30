#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IMAP IDLE 秒推到 Telegram：
- 实时：服务器推送新信事件（RFC 2177）
- 轻量抓取：仅抓头部 + 纯文本，避免大附件
- 去重持久化：seen_uids.json，重启不重复
- 时区：默认 Asia/Shanghai（修复“差 8 小时”）
- 两条消息：①时间+谁发给谁 ②纯6位验证码
- 连接策略：优先 SSL(993)，失败回退到 STARTTLS(143)
"""
import os, re, json, time, email, requests, ssl, socket
from datetime import datetime, timezone
from email.header import decode_header, make_header
from email.utils import parsedate_to_datetime
from imapclient import IMAPClient
from zoneinfo import ZoneInfo

# ---------- .env ----------
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

IMAP_HOST = os.getenv("IMAP_HOST", "imap.2925.com")
IMAP_PORT_SSL = int(os.getenv("IMAP_PORT_SSL", "993"))
IMAP_PORT_STARTTLS = int(os.getenv("IMAP_PORT_STARTTLS", "143"))
IMAP_FOLDER = os.getenv("IMAP_FOLDER", "INBOX")

MAIL_USER = os.getenv("MAIL_USER", "")
MAIL_PASS = os.getenv("MAIL_PASS", "")

TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "")
TG_CHAT_ID   = os.getenv("TG_CHAT_ID", "")

TIMEZONE = os.getenv("TIMEZONE", "Asia/Shanghai")
CODE_REGEX = os.getenv("CODE_REGEX", r"(?<!\d)(\d{6})(?!\d)")
FETCH_STARTUP_LAST_N = int(os.getenv("FETCH_STARTUP_LAST_N", "2"))
IDLE_KEEPALIVE_SECONDS = int(os.getenv("IDLE_KEEPALIVE_SECONDS", "25"))
DEDUP_DB_PATH = os.getenv("DEDUP_DB_PATH", ".seen_uids.json")

code_pat = re.compile(CODE_REGEX)
local_tz = ZoneInfo(TIMEZONE)

def send_tg(text: str):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        print("⚠️ 未配置 TG_BOT_TOKEN / TG_CHAT_ID：", text)
        return
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    for _ in range(3):
        try:
            r = requests.post(url, json={"chat_id": TG_CHAT_ID, "text": text}, timeout=8)
            if r.ok:
                return
        except Exception:
            time.sleep(0.8)

def fmt_dt(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(local_tz).strftime("%Y-%m-%d %H:%M:%S")

def decode_str(s: str) -> str:
    try:
        return str(make_header(decode_header(s or "")))
    except Exception:
        return s or ""

def load_seen() -> set:
    try:
        with open(DEDUP_DB_PATH, "r", encoding="utf-8") as f:
            return set(json.load(f))
    except Exception:
        return set()

def save_seen(seen: set):
    try:
        with open(DEDUP_DB_PATH, "w", encoding="utf-8") as f:
            json.dump(sorted(list(seen))[-10000:], f)
    except Exception:
        pass

def extract_codes(text: str):
    return code_pat.findall(text or "")

def parse_email(raw_bytes: bytes):
    msg = email.message_from_bytes(raw_bytes)
    subject = decode_str(msg.get("Subject", ""))
    from_   = decode_str(msg.get("From", ""))
    to_     = decode_str(msg.get("To", ""))
    date_hdr = msg.get("Date")
    try:
        dt = parsedate_to_datetime(date_hdr)
    except Exception:
        dt = datetime.now(timezone.utc)

    body_texts = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp  = str(part.get("Content-Disposition") or "").lower()
            if ctype == "text/plain" and "attachment" not in disp:
                try:
                    body_texts.append(part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="ignore"))
                except Exception:
                    pass
    else:
        try:
            body_texts.append(msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8", errors="ignore"))
        except Exception:
            pass
    body = "\n".join(body_texts)
    return subject, from_, to_, dt, body

def handle_messages(server: IMAPClient, uids, seen_uids: set):
    uids = sorted(uids)
    if not uids:
        return
    fetch_map = server.fetch(uids, [b'RFC822.HEADER', b'BODY.PEEK[TEXT]', b'ENVELOPE'])
    for uid in uids:
        if uid in seen_uids:
            continue
        data = fetch_map.get(uid, {})
        raw_header = data.get(b'RFC822.HEADER') or b""
        raw_text   = data.get(b'BODY[TEXT]') or b""
        raw_bytes  = raw_header + b"\r\n" + raw_text

        subject, from_, to_, dt, body = parse_email(raw_bytes)
        codes = extract_codes(subject) or extract_codes(body)

        # 两条消息
        send_tg(f"{fmt_dt(dt)}    {from_}  →  {to_}")
        send_tg(codes[0] if codes else "未识别到验证码")

        seen_uids.add(uid)
    save_seen(seen_uids)

def connect_imap() -> IMAPClient:
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = True
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # 优先 993/SSL
    try:
        c = IMAPClient(IMAP_HOST, port=IMAP_PORT_SSL, ssl=True, ssl_context=ssl_ctx, timeout=20)
        c.login(MAIL_USER, MAIL_PASS)
        return c
    except Exception:
        # 回退 143/STARTTLS
        c = IMAPClient(IMAP_HOST, port=IMAP_PORT_STARTTLS, ssl=False, timeout=20)
        c.starttls(ssl_context=ssl_ctx)
        c.login(MAIL_USER, MAIL_PASS)
        return c

def idle_loop():
    seen_uids = load_seen()
    while True:
        try:
            with connect_imap() as server:
                server.select_folder(IMAP_FOLDER, readonly=True)

                # 启动仅补扫最近 N 封
                all_uids = server.search(['ALL'])
                bootstrap = sorted(all_uids)[-FETCH_STARTUP_LAST_N:] if FETCH_STARTUP_LAST_N > 0 else []
                handle_messages(server, bootstrap, seen_uids)

                while True:
                    # 进入 IDLE 等待推送；每 ~25s 发一次 keepalive
                    server.idle()
                    server.idle_check(timeout=IDLE_KEEPALIVE_SECONDS)
                    server.idle_done()

                    latest = sorted(server.search(['ALL']))[-20:]
                    fresh = [u for u in latest if u not in seen_uids]
                    if fresh:
                        handle_messages(server, fresh, seen_uids)

        except (socket.timeout, ssl.SSLError, ConnectionError):
            time.sleep(1.5)
        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(2.5)

if __name__ == "__main__":
    idle_loop()
