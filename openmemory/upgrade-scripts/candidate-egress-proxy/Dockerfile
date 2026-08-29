FROM python:3.12-slim@sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203

WORKDIR /proxy
COPY proxy.py allowlist.json ./
RUN chmod 0555 /proxy/proxy.py /proxy/allowlist.json && mkdir -p /proxy/logs && chown 65532:65532 /proxy/logs

USER 65532:65532
EXPOSE 20128 11434
ENTRYPOINT ["/usr/bin/env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin", "PROXY_CONFIG=/proxy/allowlist.json", "PROXY_LOG_DIR=/proxy/logs", "python", "/proxy/proxy.py"]
