# أكاديمية SCROL — production image (Fly.io)
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1
EXPOSE 8080

# Initialize/seed the database once (idempotent — creates tables if missing,
# only seeds demo data on a brand-new file), then start the app server.
# Using sh -c so $PORT (if the platform sets one) overrides the 8080 default.
CMD ["sh", "-c", "python -c 'import app; app.init_db()' && gunicorn --bind 0.0.0.0:${PORT:-8080} --workers 1 --threads 4 --timeout 60 app:app"]
