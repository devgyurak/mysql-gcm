# Runner image for the E2E scenarios: a MySQL client library and nothing else.
FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

WORKDIR /e2e
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY runner.py .
COPY scenarios ./scenarios

CMD ["python", "-u", "runner.py"]
