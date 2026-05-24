from django.http import HttpResponseRedirect


class CanonicalLoopbackHostMiddleware:
    """
    Passkeys/WebAuthn are more reliable on localhost than on 127.0.0.1.
    Redirect loopback IP requests to localhost so browser credential APIs
    use a stable, valid relying-party host during local development.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        host = request.get_host()
        hostname, _, port = host.partition(":")
        if hostname == "127.0.0.1":
            target_host = "localhost"
            if port:
                target_host = f"{target_host}:{port}"
            return HttpResponseRedirect(f"{request.scheme}://{target_host}{request.get_full_path()}")
        return self.get_response(request)
