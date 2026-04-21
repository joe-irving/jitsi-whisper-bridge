# syntax=docker/dockerfile:1

ARG PYTHON_VERSION=3.14.2-alpine3.22
FROM python:3-alpine3.22

# Prevents Python from writing pyc files.
ENV PYTHONDONTWRITEBYTECODE=1

# Keeps Python from buffering stdout and stderr to avoid situations where
# the application crashes without emitting any logs due to buffering.
ENV PYTHONUNBUFFERED=1

# ENV WHISPER_URL=http://whisper.cpp:8080

WORKDIR /app

# Download dependencies as a separate step to take advantage of Docker's caching.
# Leverage a cache mount to /root/.cache/pip to speed up subsequent builds.
# Leverage a bind mount to requirements.txt to avoid having to copy them into
# into this layer.
RUN --mount=type=cache,target=/root/.cache/pip \
    --mount=type=bind,source=requirements.txt,target=requirements.txt \
    python3 -m pip install -r requirements.txt

COPY jitsi-whisper-bridge.py ./app.py



# Run the application.
CMD ["python3", "/app/app.py", "-c", "/etc/whisper-bridge/config.yml"]
