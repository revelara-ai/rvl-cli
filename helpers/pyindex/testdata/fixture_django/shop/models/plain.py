class Lookup(object):
    def get(self, key):
        return key


class Registry(object):
    """Not a Django model: `objects` here is this class's own attribute."""

    objects = Lookup()
