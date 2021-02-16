import functools
from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse

app = FastAPI()


@functools.lru_cache
def session(id: str) -> Session:
    ...


@app.get("/items/", response_class=HTMLResponse)
async def homepage(response: Response):
    response.set_cookie("session", "fixme")
    return """
    <html>
        <head>
            <title>Example client that implements OpenID Connect confidential client using code flow</title>
        </head>
        <body>
        </body>
    </html>
    """.strip()
