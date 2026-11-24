FROM python:3.12-slim

RUN groupadd -r vaultguard && useradd -r -g vaultguard -d /home/vaultguard -m vaultguard
WORKDIR /app

COPY --chown=vaultguard:vaultguard . /app

ENV PYTHONPATH=/app
USER vaultguard

ENTRYPOINT ["python3", "-m", "vaultguard.cli"]
CMD ["--help"]
