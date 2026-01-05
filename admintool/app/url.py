from django.contrib import admin
from django.urls import path, re_path
from . import views

urlpatterns = [
    path('admin/', admin.site.urls),

    path('', views.user_login, name='login'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),

    path('dashboard/', views.dashboard, name='dashboard'),
    path('user/<str:username>/', views.getuser, name='getuser'),

    path('updatedata/<path:filename>/', views.updatedata, name='updatedata'),
    path('forgot-password/', views.forgot_password, name='forgot-password'),

    # ✅ ONE dynamic route — replaces ALL Section-based URLs
    re_path(
        r'^(?P<section>[\w-]+)/(?P<filename>.*)?$',
        views.browser,
        name='browser'
    ),
]
