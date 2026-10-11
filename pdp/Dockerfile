FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --system --uid 10001 ztpdp && mkdir -p /var/log/zt-pdp && chown ztpdp:ztpdp /var/log/zt-pdp
USER ztpdp
EXPOSE 8443
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8443", "--ssl-keyfile", "/run/certs/pdp.key", "--ssl-certfile", "/run/certs/pdp.crt", "--ssl-ca-certs", "/run/certs/ca-chain.crt", "--ssl-cert-reqs", "2"]
