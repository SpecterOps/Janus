# ---- builder stage ----
FROM python:3.13-slim AS builder

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir "setuptools>=68.0" && \
    pip install --no-cache-dir --no-build-isolation --prefix=/install .

# ---- runtime stage ----
FROM python:3.13-slim

COPY --from=builder /install /usr/local
WORKDIR /data

ENTRYPOINT ["janus"]
