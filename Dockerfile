FROM python:3.12-slim

WORKDIR /gateway

# System deps: libpq not needed, but gcc is for hiredis
RUN apt-get update && apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
# vault/ is mounted at runtime via K8s secret volume — never baked into the image.

ENV GROUP=prod \
    PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
