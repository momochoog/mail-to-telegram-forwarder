FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY 2925_to_telegram_pop3_autorefresh.py ./

CMD ["python", "2925_to_telegram_pop3_autorefresh.py"]
