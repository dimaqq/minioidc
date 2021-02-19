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
    && apk del req-deps

EXPOSE 8000
COPY server.py /app/
ENTRYPOINT ["poetry", "run", "uvicorn", "server:app", "--host", ""]
