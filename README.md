# Mail to Telegram Forwarder (2925 POP3)

自动从 2925 邮箱读取验证码并转发到 Telegram。已为 Railway 部署准备好：`requirements.txt`、`Dockerfile`、启动命令和 `.env` 模板。

## 一键部署步骤（Railway）
1. 在 GitHub 新建仓库，把本项目 4 个文件上传（**不要上传 .env**）。
2. Railway → New Project → **Deploy from GitHub Repo** → 选此仓库。
3. 打开 **Settings → Variables**，把下面 `.env` 内容整段粘贴（或逐条添加）。
4. 打开 **Settings → Service Type**，改为 **Background Worker**（无端口）。
5. 打开 **Settings → Start Command**，填：
   
   ```
   python 2925_to_telegram_pop3_autorefresh.py
   ```
6. Deploy，进入 **Logs** 看到“✅ POP3 验证码监听已启动”即成功。

## 环境变量（.env 模板示例）
> 复制下面内容到 Railway 的 **Variables → Bulk Import** 即可。

```env
POP3_HOST=pop3.2925.com
POP3_PORT_SSL=995
POP3_PORT_PLAIN=110

EMAIL_USER=yibanquanru@2925.com
EMAIL_PASS=7221272plm

TELEGRAM_BOT_TOKEN=8410837583:AAEnCCOrhQ5eD7TelLnse2ZkXr8FRp2Bzls
TELEGRAM_CHAT_ID=8378750157
# 如需代理：TG_PROXY=socks5h://127.0.0.1:1080
```

## 说明
- 这是一个 **后台 Worker** 程序，不暴露端口；Railway 上必须设置成 Background Worker。
- 若报 429，脚本内置了 retry_after 处理，会自动缓解。
- 启动时最多读取最近 2 封验证码（避免刷历史），之后 1 秒轮询收取新邮件。
- 可在脚本顶部修改：轮询间隔 `POLL_SECONDS`、启动历史 `FETCH_STARTUP_LAST_N` 等。
- 长期 24×7 运行建议使用 Railway 付费计划，避免试用到期/休眠。
