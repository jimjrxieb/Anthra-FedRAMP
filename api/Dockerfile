# DELIBERATELY INSECURE — runs as root, no healthcheck, no multi-stage
FROM python:3.11  # SECURITY: Add HEALTHCHECK instruction to Dockerfile
# SECURITY: Add HEALTHCHECK instruction
# HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost/ || exit 1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
