from functools import wraps

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect

from .models import User


def mfa_verified_required(view_func):
    @login_required
    @wraps(view_func)
    def wrapped(request, *args, **kwargs):
        if not request.session.get("mfa_verified"):
            messages.error(request, "Please complete multi-factor verification first.")
            return redirect("accounts:choose-factor")
        return view_func(request, *args, **kwargs)

    return wrapped


def role_required(role):
    def decorator(view_func):
        @mfa_verified_required
        @wraps(view_func)
        def wrapped(request, *args, **kwargs):
            if request.user.role != role:
                messages.error(request, "You do not have permission to access that page.")
                return redirect("accounts:dashboard")
            return view_func(request, *args, **kwargs)

        return wrapped

    return decorator


admin_required = role_required(User.Role.ADMIN)
