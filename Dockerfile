FROM python:3.10
SHELL ["/bin/bash", "-c"]

WORKDIR /app/service
COPY ./requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY ./README.md ./README.md
COPY ./karton ./karton
COPY ./setup.py ./setup.py
RUN pip install .
ENTRYPOINT karton-misp-pusher

