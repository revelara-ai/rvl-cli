import hashlib
import ssl

import httpx
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from sqlalchemy import create_engine
import psycopg2
from psycopg2 import connect as pg_connect


def insecure_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def unverified():
    return ssl._create_unverified_context()


def digest(data):
    return hashlib.md5(data).hexdigest()


def ecb(key):
    return Cipher(algorithms.AES(key), modes.ECB())


def client():
    return httpx.Client(verify=False)


def engine():
    return create_engine("postgresql://app:hunter2@db/app")


def module_connect():
    return psycopg2.connect("dbname=app password=hunter2")


def imported_connect():
    return pg_connect("dbname=app password=hunter2")


def not_a_construction(cache):
    cache.md5(b"x")
    return cache.CERT_NONE
