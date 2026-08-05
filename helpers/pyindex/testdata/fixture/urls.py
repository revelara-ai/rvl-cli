"""G2 server-entry fixture: django URL configuration. Registration is by the
import-resolved function name, so a local helper named `path` never matches."""

from django.urls import path, re_path

import views


urlpatterns = [
    path("users/", views.users),
    re_path(r"^status/$", views.status),
]
