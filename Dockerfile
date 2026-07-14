FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY byte_pattern_extractor.py elf_parser.py entropy.py feature_extractor.py \
     main.py rule_builder.py string_filter.py suspicious_imports.py \
     worker_entrypoint.py ./
COPY whitelist/ ./whitelist/

ENTRYPOINT ["python3", "worker_entrypoint.py"]
