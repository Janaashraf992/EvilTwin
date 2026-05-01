FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 ryu

COPY requirements.txt .
RUN pip install --no-cache-dir "setuptools<58" && \
    pip install --no-cache-dir -r requirements.txt && \
    sed -i 's/from eventlet.wsgi import ALREADY_HANDLED/ALREADY_HANDLED = b""/g' \
        /usr/local/lib/python3.11/site-packages/ryu/app/wsgi.py

COPY --chown=ryu:ryu . .

USER ryu

EXPOSE 6633
EXPOSE 8080

CMD ["ryu-manager", "--observe-links", "controller.py"]
