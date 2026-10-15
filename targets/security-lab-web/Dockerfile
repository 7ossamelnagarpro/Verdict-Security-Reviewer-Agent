FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --uid 10001 --create-home lab \
    && chown lab:lab /app

COPY --chown=lab:lab . ./
USER lab
EXPOSE 5000

CMD ["python", "-c", "from app import app, init_db; init_db(); app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)"]
