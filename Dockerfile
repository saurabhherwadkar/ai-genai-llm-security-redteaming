# Multi-stage Dockerfile for the LLM security red-teaming service
# Stage 1: Build dependencies using Poetry
# Stage 2: Run the application with minimal image

FROM python:3.11-slim as builder

WORKDIR /app

# Install Poetry
RUN pip install --no-cache-dir poetry==1.8.4

# Copy dependency files
COPY pyproject.toml poetry.lock* ./

# Export to requirements.txt
RUN poetry export -f requirements.txt --without-hashes --output requirements.txt

# Runtime stage
FROM python:3.11-slim as runtime

WORKDIR /app

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash appuser

# Install dependencies
COPY --from=builder /app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY src/ ./src/
COPY config/ ./config/

# Create directories with proper permissions
RUN mkdir -p logs reports/output && chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Set Python path
ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; r = httpx.get('http://localhost:8000/api/v1/security/health'); r.raise_for_status()"

# Run the application
CMD ["python", "-m", "uvicorn", "security_redteaming.main:app", "--host", "0.0.0.0", "--port", "8000"]
