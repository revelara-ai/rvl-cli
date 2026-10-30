import ssl


def _get_verify():
    return True


# The shapes of a TLS opt-out measured in open-source Python: each setting
# sits under the `if` or the conditional expression that turns it on.


class Auth:
    def __init__(self, insecure):
        self._insecure_skip_tls_verify = insecure

    # An attribute of the object, set from the caller's option.
    def context(self):
        ctx = ssl.create_default_context()
        if self._insecure_skip_tls_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx


# A local assigned from a call: an `is False` test of it.
def stream_options():
    verify = _get_verify()
    sslopt = {}
    if verify is False:
        sslopt = {"cert_reqs": ssl.CERT_NONE, "check_hostname": False}
    return sslopt


# A keyword parameter, tested in a conditional expression.
def send(ctx, *args, verify=True, **kwargs):
    ctx.verify_mode = ssl.CERT_NONE if not verify else ssl.CERT_REQUIRED
    return ctx


# A parameter in a conjunction with a call.
def health_ok(url, ctx, verify: bool = True):
    if url.startswith("https://") and not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


# The else branch runs when the option is off; the walk stops at a closure.
def verified(options, ctx):
    if options.ssl_verify:
        ctx.load_default_certs()
    else:
        ctx.check_hostname = False
    if options.ssl_insecure:
        return lambda: ssl.CERT_NONE
    return None
