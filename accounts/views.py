import time
import logging
from typing import Optional

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate, get_user_model, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import (
    PasswordResetView, 
    PasswordResetDoneView, 
    PasswordResetConfirmView, 
    PasswordResetCompleteView
)
from django.http import HttpRequest, HttpResponse
from django.core.cache import cache
from django.core.mail import send_mail, EmailMultiAlternatives
from django.core.signing import Signer, BadSignature
from django.core.exceptions import ObjectDoesNotExist
from django.utils.http import url_has_allowed_host_and_scheme, urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.urls import reverse, reverse_lazy
from django.conf import settings
from django import forms
from django.db import models, transaction
from django.core.paginator import Paginator

from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp import login as otp_login

from .forms import EmailAuthenticationForm, TOTPForm, JobSeekerSignupForm, AdminUserCreationForm, UserProfileForm, CustomPasswordChangeForm
from .models import User, JobSeekerProfile
from .tokens import account_activation_token
from .decorators import redirect_authenticated_user, admin_required, job_seeker_required
from .email_threading import send_async_email

logger = logging.getLogger(__name__)
signer = Signer()

# Constants
RATE_LIMIT_SECONDS = 60
TRUSTED_DEVICE_COOKIE = getattr(settings, 'TRUSTED_DEVICE_COOKIE', 'trusted_device')
TRUSTED_DEVICE_MAX_AGE = getattr(settings, 'TRUSTED_DEVICE_MAX_AGE', 30 * 24 * 60 * 60)  # 30 days


class ResendActivationForm(forms.Form):
    email = forms.EmailField(label="Email", max_length=254)


# Utility Functions
def _set_trusted_device(response: HttpResponse, user: User) -> None:
    """Set trusted device cookie for bypassing 2FA."""
    value = signer.sign(f"{user.pk}")
    response.set_cookie(
        TRUSTED_DEVICE_COOKIE,
        value,
        max_age=TRUSTED_DEVICE_MAX_AGE,
        secure=True,
        httponly=True,
        samesite="Lax",
    )


def _has_trusted_device(request: HttpRequest, user: User) -> bool:
    """Check if user has a trusted device cookie."""
    cookie = request.COOKIES.get(TRUSTED_DEVICE_COOKIE)
    if not cookie:
        return False
    
    try:
        raw = signer.unsign(cookie)
        return raw == str(user.pk)
    except BadSignature:
        return False


def _send_activation_email(user: User, request: HttpRequest, subject_suffix: str = "") -> None:
    """Send activation email to the user."""
    try:
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = account_activation_token.make_token(user)
        activation_link = request.build_absolute_uri(
            reverse("accounts:activate", kwargs={"uidb64": uid, "token": token})
        )

        subject = f"Verify Your Email Address{subject_suffix}"
        context = {
            'first_name': user.first_name,
            'activation_link': activation_link,
            'user': user,
        }

        send_async_email(
            subject=subject,
            template_name='accounts/email/email_verification.html',
            context=context,
            to_email=user.email
        )
    except Exception as e:
        logger.error(f"Failed to send activation email to {user.email}: {e}")
        raise


def _handle_successful_login(request: HttpRequest, user: User, form) -> HttpResponse:
    """Handle post-login logic including 2FA and redirects."""
    login(request, user, backend='accounts.backends.EmailBackend')
    request.session.set_expiry(60 * 60 * 12 if form.cleaned_data.get("remember_me") else 0)

    # Check for 2FA
    device = TOTPDevice.objects.filter(user=user, confirmed=True).first()
    if device and not _has_trusted_device(request, user):
        request.session["otp_user_id"] = user.pk
        return redirect("accounts:otp_verify")

    messages.success(request, f"Welcome back, {user.first_name or user.email}!")

    redirect_to = request.GET.get("next") or request.POST.get("next")
    if redirect_to and url_has_allowed_host_and_scheme(
        url=redirect_to, allowed_hosts={request.get_host()}
    ):
        return redirect(redirect_to)

    return redirect(settings.LOGIN_REDIRECT_URL)


# Authentication Views
@redirect_authenticated_user
def login_view(request: HttpRequest) -> HttpResponse:
    """Handle user login with support for inactive accounts and 2FA."""
    form = EmailAuthenticationForm(request.POST or None)
    inactive_user = None

    if request.method == "POST":
        if "resend_activation" in request.POST:
            email = request.POST.get("email")
            try:
                user = User.objects.get(email=email, is_active=False)
                _send_activation_email(user, request, " - New Activation Link")
                messages.success(request, "Activation email has been resent. Please check your inbox.")
                inactive_user = user
            except User.DoesNotExist:
                messages.error(request, "No inactive account found with this email address.")
                
        elif form.is_valid():
            email = form.cleaned_data.get('email')
            password = form.cleaned_data.get('password')
            
            user = authenticate(
                request,
                username=email,
                password=password,
                backend='accounts.backends.EmailBackend'
            )

            if not user:
                messages.error(
                    request, 
                    "The email address or password you entered is incorrect. Please try again."
                )
            elif not user.is_active:
                inactive_user = user
                messages.error(
                    request, 
                    "Your account has not been activated yet. Please check your email for the activation link."
                )
            else:
                return _handle_successful_login(request, user, form)
        else:
            messages.error(request, "Please correct the errors below.")

    return render(request, "accounts/login.html", {
        "form": form,
        "inactive_user": inactive_user,
    })


def logout_view(request: HttpRequest) -> HttpResponse:
    """Handle user logout."""
    logout(request)
    messages.info(request, "You have been logged out.")
    return redirect("accounts:login")


@login_required
def otp_setup(request: HttpRequest) -> HttpResponse:
    """Setup TOTP device for 2FA."""
    # Get or create device
    device, created = TOTPDevice.objects.get_or_create(
        user=request.user, 
        name="default"
    )
    
    if not device.key:
        device.generate_key()
        device.save()
    
    # Check if device is already confirmed
    if device.confirmed:
        messages.info(request, "Two-factor authentication is already set up for your account.")
        return redirect('user_profile')
    
    uri = device.config_url
    
    # Handle verification during setup
    if request.method == "POST":
        form = TOTPForm(request.POST)
        if form.is_valid():
            token = form.cleaned_data["token"]
            
            if device.verify_token(token):
                # Confirm the device
                device.confirmed = True
                device.save()
                
                messages.success(request, "Two-factor authentication has been successfully set up!")
                return redirect('user_profile')
            else:
                messages.error(request, "Invalid verification code. Please try again.")
    else:
        form = TOTPForm()
    
    return render(request, "accounts/otp_setup.html", {
        "uri": uri, 
        "device": device,
        "form": form
    })


def otp_verify(request: HttpRequest) -> HttpResponse:
    """Verify TOTP token for 2FA."""
    user_id = request.session.get("otp_user_id")
    if not user_id:
        return redirect("accounts:login")

    form = TOTPForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            user = User.objects.get(pk=user_id)
            device = TOTPDevice.objects.filter(user=user, confirmed=True).first()
            
            if device and device.verify_token(form.cleaned_data["token"]):
                otp_login(request, device)
                response = redirect(settings.LOGIN_REDIRECT_URL)
                
                if form.cleaned_data.get("trust_device"):
                    _set_trusted_device(response, user)
                
                messages.success(request, "2FA verified.")
                request.session.pop("otp_user_id", None)
                return response
            
            messages.error(request, "Invalid token. Please try again.")
        except User.DoesNotExist:
            messages.error(request, "User not found.")
            return redirect("accounts:login")

    return render(request, "accounts/otp_verify.html", {"form": form})



@login_required
def otp_disable(request: HttpRequest) -> HttpResponse:
    """Disable 2FA for the current user (handles modal form submission)."""
    if request.method == "POST":
        password = request.POST.get('password')
        
        if not password:
            messages.error(request, "Please enter your password to disable 2FA.")
            return redirect('user_profile')
        
        # Authenticate the user with their password
        user = authenticate(request, username=request.user.email, password=password)
        if user is None:
            messages.error(request, "Invalid password. Please try again.")
            return redirect('user_profile')
        
        # Delete all TOTP devices for this user
        devices_deleted = TOTPDevice.objects.filter(user=request.user).delete()
        
        messages.success(request, "Two-factor authentication has been disabled for your account.")
        return redirect('user_profile')
    
    # If not POST, redirect to profile
    return redirect('user_profile')


@login_required
def otp_disable_confirm(request: HttpRequest) -> HttpResponse:
    """Confirmation page for disabling 2FA."""
    # Check if user actually has 2FA enabled
    has_2fa = TOTPDevice.objects.filter(user=request.user, confirmed=True).exists()
    if not has_2fa:
        messages.info(request, "Two-factor authentication is not enabled for your account.")
        return redirect('user_profile')
    
    return render(request, "accounts/otp_disable_confirm.html")



# Registration & Activation Views
@redirect_authenticated_user
def jobseeker_signup(request: HttpRequest) -> HttpResponse:
    """Handle job seeker registration."""
    if request.method == "POST":
        form = JobSeekerSignupForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                user = form.save(commit=True)
                _send_activation_email(user, request)
                
                messages.success(request, "Registration successful! Please check your email to verify your account.")
                return render(request, "accounts/email/email_verification_sent.html", {'user': user})
                
            except Exception as e:
                logger.error(f"Registration error for {form.cleaned_data.get('email')}: {e}")
                messages.warning(
                    request, 
                    "Account created successfully! However, we encountered an issue sending the verification email. Please contact support."
                )
                return render(request, "accounts/email/email_verification_sent.html", {'user': user})
    else:
        form = JobSeekerSignupForm()

    return render(request, "accounts/signup.html", {"form": form})


def activate(request: HttpRequest, uidb64: str, token: str) -> HttpResponse:
    """Activate user account via email verification."""
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user and account_activation_token.check_token(user, token):
        user.is_active = True
        user.email_verified = True
        user.save()
        return render(request, "accounts/activation_success.html", {"user": user})
    else:
        return render(request, "accounts/activation_failed.html")


@redirect_authenticated_user
def resend_activation(request: HttpRequest) -> HttpResponse:
    """Resend activation email with rate limiting."""
    if request.method == "POST":
        form = ResendActivationForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data["email"].lower()
            cache_key = f"resend_activation_{email}"
            last_sent = cache.get(cache_key)
            now = time.time()

            if last_sent and now - last_sent < RATE_LIMIT_SECONDS:
                wait_time = int(RATE_LIMIT_SECONDS - (now - last_sent))
                messages.error(
                    request, 
                    f"Please wait {wait_time} seconds before requesting another activation email."
                )
                return redirect("accounts:resend_activation")

            try:
                user = User.objects.get(email__iexact=email)
            except User.DoesNotExist:
                messages.success(
                    request, 
                    "If an account exists for this email, an activation link has been sent."
                )
                return redirect("accounts:login")

            if user.is_active:
                messages.info(request, "This account is already active. You can log in.")
                return redirect("accounts:login")

            try:
                _send_activation_email(user, request, " - New Activation Link")
                cache.set(cache_key, now, RATE_LIMIT_SECONDS)
                messages.success(request, "Activation email resent. Check your inbox.")
                return redirect("accounts:login")
            except Exception as e:
                logger.error(f"Failed to resend activation email to {email}: {e}")
                messages.error(request, "Failed to send activation email. Please try again later.")
    else:
        form = ResendActivationForm()

    return render(request, "accounts/resend_activation.html", {"form": form})


def resend_activation_for_user(request: HttpRequest, user_id: int) -> HttpResponse:
    """Resend activation for a specific user (used in activation failed page)."""
    try:
        user = User.objects.get(pk=user_id, is_active=False)
        _send_activation_email(user, request, " - New Activation Link")
        messages.success(request, "A new activation link has been sent to your email.")
        return redirect('accounts:activation_sent')
    except User.DoesNotExist:
        messages.error(request, "User not found or account is already active.")
        return redirect('accounts:login')


# Password Reset Views
class CustomPasswordResetView(PasswordResetView):
    """Custom Password Reset View with threaded email sending and HTML support"""
    template_name = 'accounts/password_reset.html'
    email_template_name = 'accounts/email/password_reset_email.txt'
    html_email_template_name = 'accounts/email/password_reset_email.html'
    subject_template_name = 'accounts/email/password_reset_subject.txt'
    success_url = reverse_lazy('accounts:password_reset_done')

    def send_mail(self, subject_template_name, email_template_name, context, from_email, to_email, html_email_template_name=None):
        """Override Django's default send_mail to send email asynchronously."""
        try:
            subject = render_to_string(subject_template_name, context)
            subject = ''.join(subject.splitlines()).strip()

            html_template = html_email_template_name or self.html_email_template_name or email_template_name

            send_async_email(
                subject=subject,
                template_name=html_template,
                context=context,
                to_email=to_email
            )
        except Exception as e:
            logger.error(f"Error in password reset email: {str(e)}")

    def form_valid(self, form):
        """Called when the form is valid — after email is sent."""
        response = super().form_valid(form)
        messages.success(
            self.request,
            "If an account with that email exists, we've sent password reset instructions to your email."
        )
        return response


class CustomPasswordResetDoneView(PasswordResetDoneView):
    template_name = 'accounts/password_reset_done.html'


class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'accounts/password_reset_confirm.html'
    success_url = reverse_lazy('accounts:password_reset_complete')
    
    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, "Your password has been reset successfully!")
        return response


class CustomPasswordResetCompleteView(PasswordResetCompleteView):
    template_name = 'accounts/password_reset_complete.html'




# ERRORS PAGES
def error_404(request, exception):
    return render(request, 'error/404.html', status=404)

def error_500(request):
    return render(request, 'error/500.html', status=500)

def error_503(request):
    return render(request, 'error/503.html', status=503)

def error_401(request, exception=None):
    return render(request, 'error/401.html', status=401)

def error_403(request, exception=None):
    return render(request, 'error/403.html', status=403)