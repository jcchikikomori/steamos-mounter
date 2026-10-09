ARG PYTHON_VERSION=3.14
FROM python:${PYTHON_VERSION}-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends rsync shellcheck ntfs-3g \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
COPY requirements-dev.txt /tmp/requirements-dev.txt
RUN pip install --no-cache-dir -r /tmp/requirements-dev.txt
ENV PYTHONDONTWRITEBYTECODE=1
