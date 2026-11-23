FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN useradd --create-home --shell /bin/bash omni
WORKDIR /app

COPY pyproject.toml README.md llms.txt LICENSE ./
COPY src ./src
COPY constitution ./constitution

RUN pip install --upgrade pip && pip install -e . pytest

USER omni
ENTRYPOINT ["omni-executor"]
CMD ["doctor"]
