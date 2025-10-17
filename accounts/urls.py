from django.urls import path
from . import views
from job.views_pkg import jobseeker_signup

app_name = "accounts"

urlpatterns = [
    # Authentication URLs
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    
    # OTP URLs
    path("otp/setup/", views.otp_setup, name="otp_setup"),
    path("otp/verify/", views.otp_verify, name="otp_verify"),
    path("otp/disable/", views.otp_disable, name="otp_disable"),
    path("otp/disable/confirm/", views.otp_disable_confirm, name="otp_disable_confirm"),
    path('otp/debug/', views.otp_debug, name='otp_debug'),
    path('otp/reset/', views.otp_reset, name='otp_reset'),
    path('otp/emergency-fix/', views.otp_emergency_fix, name='otp_emergency_fix'),
    
    # Registration & Activation URLs
    path("signup/", jobseeker_signup, name="jobseeker_signup"),
    path("activate/<uidb64>/<token>/", views.activate, name="activate"),
    path("resend-activation/", views.resend_activation, name="resend_activation"),
    
    # Password Reset URLs
    path('password-reset/', views.CustomPasswordResetView.as_view(), name='password_reset'),
    path('password-reset/done/', views.CustomPasswordResetDoneView.as_view(), name='password_reset_done'),
    path('password-reset-confirm/<uidb64>/<token>/', views.CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('password-reset-complete/', views.CustomPasswordResetCompleteView.as_view(), name='password_reset_complete'),
]

