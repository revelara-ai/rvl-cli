"""G2 server-entry fixture (po-av01j.3): flask + fastapi registration
surfaces. Only the AST is parsed -- neither framework needs to be installed."""

from flask import Flask, Blueprint
from fastapi import FastAPI, APIRouter

from middlewares import RequestIdMiddleware

app = Flask(__name__)
bp = Blueprint("api", __name__)
api = FastAPI()
router = APIRouter()


@app.route("/healthz")
def healthz():
    return "ok"


@bp.route("/users")
def users():
    return []


@api.get("/orders")
async def orders():
    return []


@api.middleware("http")
async def add_request_id(request, call_next):
    return await call_next(request)


@app.before_request
def audit():
    pass


api.add_middleware(RequestIdMiddleware)
api.include_router(router)
app.add_url_rule("/legacy", view_func=users)
