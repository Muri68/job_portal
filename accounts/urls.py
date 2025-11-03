# urls.py
from django.urls import path
from . import views

app_name = "accounts"

urlpatterns = [
    # Authentication URLs
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    
    # OTP URLs
    path("otp/setup/", views.setup_otp, name="otp_setup"),
    path("otp/verify/", views.verify_otp, name="otp_verify"),
    path("otp/disable/", views.otp_disable, name="otp_disable"),
    path("otp/disable/confirm/", views.otp_disable_confirm, name="otp_disable_confirm"),
    
    # Registration & Activation URLs
    path("signup/", views.jobseeker_signup, name="jobseeker_signup"),
    path("activate/<uidb64>/<token>/", views.activate, name="activate"),
    path("resend-activation/", views.resend_activation, name="resend_activation"),
    
    # Password Reset URLs
    path('password-reset/', views.CustomPasswordResetView.as_view(), name='password_reset'),
    path('password-reset/done/', views.CustomPasswordResetDoneView.as_view(), name='password_reset_done'),
    path('password-reset-confirm/<uidb64>/<token>/', views.CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('password-reset-complete/', views.CustomPasswordResetCompleteView.as_view(), name='password_reset_complete'),
]