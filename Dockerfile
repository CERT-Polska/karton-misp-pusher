FROM python:3.14-slim-trixie

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libssl-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app/service
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt setuptools
COPY README.md ./README.md
COPY karton ./karton
COPY setup.py ./setup.py
RUN pip install .
ENTRYPOINT ["karton-misp-pusher"]
