FROM python:3.9.1-alpine3.13

COPY pyproject.toml /app/
COPY poetry.lock /app/

WORKDIR /app/
RUN apk update \
    && apk upgrade \
    && apk add -q --no-progress --virtual req-deps \
        build-base \
        cargo \
        libffi-dev \
        openssl-dev \
    && wget https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py \
    && POETRY_HOME=/etc/poetry python get-poetry.py --yes \
    && rm get-poetry.py \
    && ln -s /etc/poetry/bin/poetry /usr/local/bin/poetry \
    && poetry install --no-dev \
    && poetry run python -m compileall \
    && rm -rf /root/.cache/pip \
    && rm -rf /root/.cache/pypoetry/artifacts /root/.cache/pypoetry/cache \
    && rm -rf /root/.cargo \
    && rm -rf /etc/poetry/lib/poetry/_vendor/py2.7 \
    && rm -rf /etc/poetry/lib/poetry/_vendor/py3.5 \
    && rm -rf /etc/poetry/lib/poetry/_vendor/py3.6 \
    && rm -rf /etc/poetry/lib/poetry/_vendor/py3.7 \
    && rm -rf /etc/poetry/lib/poetry/_vendor/py3.8 \
    && apk del req-deps

EXPOSE 8000
COPY server.py /app/
ENTRYPOINT ["poetry", "run", "uvicorn", "server:app", "--host", ""]
