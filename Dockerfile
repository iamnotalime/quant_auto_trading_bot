# Pin both the Python patch line and immutable Docker Official Image manifest.
# Update this digest only through a reviewed dependency change.
FROM python:3.14.7-slim@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=0 \
    OPENBLAS_NUM_THREADS=1 \
    OMP_NUM_THREADS=1

WORKDIR /app
COPY requirements.lock ./
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock
COPY . .
RUN useradd --create-home --uid 10001 quantbot \
    && mkdir -p /app/runtime \
    && chown -R quantbot:quantbot /app
USER quantbot

EXPOSE 8501
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8501/_stcore/health', timeout=5)" || exit 1
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true"]
