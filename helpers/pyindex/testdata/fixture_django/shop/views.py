import requests

from shop.models import Order, Registry


def load_order(pk):
    return Order.objects.get(pk=pk)


def load_entry(key):
    return Registry.objects.get(key)


def fetch(url):
    return requests.get(url, timeout=5)
