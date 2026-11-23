FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends nmap ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py bot.py start.sh ./
RUN chmod +x start.sh && useradd --create-home --uid 10001 runner
USER runner
EXPOSE 10000
CMD ["sh", "start.sh"]
