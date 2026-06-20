FROM python:3.11-slim

WORKDIR /app

RUN mkdir -p /data

COPY server.py .

ENV PORT=8088
ENV EVENTS_FILE=/data/events.json

EXPOSE 8088

CMD ["python", "server.py"]
