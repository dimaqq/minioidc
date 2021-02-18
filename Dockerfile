FROM python:3.9.1-alpine3.13

COPY pyproject.toml /app/
COPY poetry.lock /app/

WORKDIR /app/
RUN apk update \
    && apk upgrade \
    && apk add -q --no-progress \
    && wget https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py \
    && POETRY_HOME=/etc/poetry python get-poetry.py --yes \
    && rm get-poetry.py \
    && ln -s /etc/poetry/bin/poetry /usr/local/bin/poetry \
    && poetry install --no-dev \
    && echo done
