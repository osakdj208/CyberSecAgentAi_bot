FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates GOMEMLIMIT=300MiB
RUN apt-get update && apt-get install -y --no-install-recommends nmap ca-certificates curl unzip && rm -rf /var/lib/apt/lists/*
# Nuclei (detection-only vulnerability scanner) - pinned release binary.
ARG NUCLEI_VERSION=3.3.0
RUN curl -sfL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei \
    && chmod +x /usr/local/bin/nuclei && rm /tmp/nuclei.zip
# Template library (build-time download; the engine reports honestly if absent).
# Prune non-web categories to keep scanner startup fast on small CPUs.
RUN nuclei -update-templates -update-template-dir /opt/nuclei-templates || true
RUN rm -rf /opt/nuclei-templates/javascript /opt/nuclei-templates/code \
           /opt/nuclei-templates/dast /opt/nuclei-templates/headless \
           /opt/nuclei-templates/file /opt/nuclei-templates/cloud \
           /opt/nuclei-templates/workflows || true
# Keep only the curated web-assessment sets under http/ (~3.2k templates):
# the CVE/technology trees alone are ~5.7k files and exceed free-tier RAM.
RUN cd /opt/nuclei-templates/http && ls | grep -v -E '^(exposures|misconfiguration|vulnerabilities|takeovers|miscellaneous)$' | xargs -r rm -rf || true
RUN chmod -R a+rX /opt/nuclei-templates 2>/dev/null || true
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py bot.py start.sh ./
RUN chmod +x start.sh && useradd --create-home --uid 10001 runner
USER runner
EXPOSE 10000
CMD ["sh", "start.sh"]
