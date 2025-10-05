from django_otp.plugins.otp_totp.models import TOTPDevice
from django.core.signing import Signer, BadSignature
from .forms import EmailAuthenticationForm, TOTPForm
from django.utils.http import url_has_allowed_host_and_scheme
from django.conf import settings
from django.core.mail import send_mail
from django.urls import reverse
from django.template.loader import render_to_string
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMultiAlternatives
from django import forms
from django.core.cache import cache
import time
from .forms import JobSeekerSignupForm
from .models import User
from .tokens import account_activation_token
signer = Signer()
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django_otp.plugins.otp_totp.models import TOTPDevice
from django.core.signing import Signer, BadSignature
from django.core.mail import send_mail
from django.utils.http import url_has_allowed_host_and_scheme
from django.conf import settings
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import get_user_model
from .forms import EmailAuthenticationForm, TOTPForm, JobSeekerSignupForm
from .models import User
from .tokens import account_activation_token
from .decorators import redirect_authenticated_user


def _set_trusted_device(response, user):
    value = signer.sign(f"{user.pk}")
    response.set_cookie(
        settings.TRUSTED_DEVICE_COOKIE,
        value,
        max_age=settings.TRUSTED_DEVICE_MAX_AGE,
        secure=True,
        httponly=True,
        samesite="Lax",
    )


def _has_trusted_device(request, user):
    cookie = request.COOKIES.get(settings.TRUSTED_DEVICE_COOKIE)
    if not cookie:
        return False
    try:
        raw = signer.unsign(cookie)
        return raw == str(user.pk)
    except BadSignature:
        return False


def send_activation_email(user, request):
    """Send activation email to the user."""
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = account_activation_token.make_token(user)
    activation_link = request.build_absolute_uri(
        reverse("accounts:activate", kwargs={"uidb64": uid, "token": token})
    )

    subject = "Activate your account"
    message = f"Hi {user.first_name},\n\nPlease click the link below to activate your account:\n{activation_link}"
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])




def login_view(request: HttpRequest) -> HttpResponse:
    form = EmailAuthenticationForm(request.POST or None)
    inactive_user = None

    if request.method == "POST":
        if "resend_activation" in request.POST:
            email = request.POST.get("email")
            try:
                user = User.objects.get(email=email, is_active=False)
                send_activation_email(user, request)
                messages.success(request, "Activation email resent. Check your inbox.")
                inactive_user = user
            except User.DoesNotExist:
                messages.error(request, "No inactive account found with this email.")
        elif form.is_valid():
            user = form.get_user()

            if not user:
                messages.error(request, "Invalid login credentials.")
            elif not user.is_active:
                inactive_user = user
                messages.error(request, "Your account is not active. Please verify your email.")
            else:
                login(request, user)
                request.session.set_expiry(
                    60 * 60 * 12 if form.cleaned_data.get("remember_me") else 0
                )

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

    return render(request, "accounts/login.html", {
        "form": form,
        "inactive_user": inactive_user,
    })

    
    

def logout_view(request: HttpRequest) -> HttpResponse:
    logout(request)
    messages.info(request, "You have been logged out.")
    return redirect("accounts:login")




from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.core.paginator import Paginator
from .models import User
from .forms import AdminUserCreationForm
from .decorators import job_seeker_required, admin_required




@login_required
@admin_required
def add_admin_user(request):
    """View to add new admin users"""
    if request.method == 'POST':
        form = AdminUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            
            # Send welcome email if requested
            if form.cleaned_data.get('send_welcome_email'):
                # You can implement email sending here
                pass
                
            messages.success(
                request, 
                f'Admin user {user.get_full_name()} has been created successfully!'
            )
            return redirect('admin_users_list')
    else:
        form = AdminUserCreationForm()
    
    return render(request, 'job/add_admin_user.html', {'form': form})


@login_required
@admin_required
def admin_users_list(request):
    """List all admin users"""
    admin_users = User.objects.filter(role=User.Role.SITE_ADMIN).order_by('-date_joined')
    
    # Pagination
    paginator = Paginator(admin_users, 10)  # Show 10 admins per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    return render(request, 'job/admin_users_list.html', {'page_obj': page_obj})

@login_required
@admin_required
def toggle_admin_status(request, user_id):
    """Activate/Deactivate admin user"""
    admin_user = get_object_or_404(User, id=user_id, role=User.Role.SITE_ADMIN)
    
    # Prevent self-deactivation
    if admin_user == request.user:
        messages.error(request, "You cannot deactivate your own account.")
        return redirect('admin_users_list')
    
    admin_user.is_active = not admin_user.is_active
    admin_user.save()
    
    status = "activated" if admin_user.is_active else "deactivated"
    messages.success(request, f"Admin user {admin_user.email} has been {status}.")
    return redirect('admin_users_list')






from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth import update_session_auth_hash
from django.contrib import messages
from django.db import models
from django.core.paginator import Paginator
from .models import User
from .forms import AdminUserCreationForm, UserProfileForm, CustomPasswordChangeForm


@login_required
@admin_required
def delete_admin_user(request, user_id):
    """Delete admin user with comprehensive protection"""
    admin_user = get_object_or_404(User, id=user_id)
    
    # Check if user can be deleted
    can_delete, error_message = admin_user.can_be_deleted(request.user)
    if not can_delete:
        messages.error(request, error_message)
        return redirect('admin_users_list')
    
    user_email = admin_user.email
    admin_user.delete()
    
    messages.success(request, f"User {user_email} has been deleted successfully.")
    return redirect('admin_users_list')


@login_required
@admin_required
def toggle_admin_status(request, user_id):
    """Activate/Deactivate admin user with comprehensive protection"""
    admin_user = get_object_or_404(User, id=user_id)
    
    # Prevent self-deactivation
    if admin_user == request.user:
        messages.error(request, "You cannot modify your own account status.")
        return redirect('admin_users_list')
    
    # Check if this is the last active superuser
    if admin_user.is_superuser and admin_user.is_active:
        active_superusers_count = User.objects.filter(
            is_superuser=True, 
            is_active=True
        ).exclude(id=admin_user.id).count()
        
        if active_superusers_count == 0:
            messages.error(
                request, 
                "Cannot deactivate the last active superuser. There must be at least one active superuser in the system."
            )
            return redirect('admin_users_list')
    
    admin_user.is_active = not admin_user.is_active
    admin_user.save()
    
    status = "activated" if admin_user.is_active else "deactivated"
    messages.success(request, f"User {admin_user.email} has been {status} successfully.")
    return redirect('admin_users_list')


@login_required
def user_profile(request):
    """User profile editing page"""
    if request.method == 'POST':
        form = UserProfileForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Your profile has been updated successfully!')
            return redirect('user_profile')
    else:
        form = UserProfileForm(instance=request.user)
    
    return render(request, 'job/user_profile.html', {
        'form': form,
        'active_tab': 'profile'
    })


@login_required
@admin_required
def change_password(request):
    """Password change page with automatic logout after success"""
    if request.method == 'POST':
        form = CustomPasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            # Logout the user after password change
            logout(request)
            messages.success(
                request, 
                'Your password has been changed successfully! Please log in again with your new password.'
            )
            return redirect('accounts:login')  # Redirect to login page
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = CustomPasswordChangeForm(request.user)
    
    return render(request, 'job/change_password.html', {
        'form': form,
        'active_tab': 'password'
    })
    

@login_required
def admin_settings(request):
    """Main settings page that redirects to profile or password"""
    return redirect('user_profile')

@login_required
@admin_required
def admin_users_list(request):
    """List all admin users with enhanced functionality"""
    admin_users = User.objects.filter(
        models.Q(role=User.Role.SITE_ADMIN) | models.Q(is_superuser=True)
    ).order_by('-date_joined')
    
    # Pagination
    paginator = Paginator(admin_users, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    return render(request, 'job/admin_users_list.html', {
        'page_obj': page_obj,
        'active_superusers_count': User.get_active_superusers_count()
    })
    
    
    




@login_required
def otp_setup(request: HttpRequest) -> HttpResponse:
    ### Create device if not exists
    device, created = TOTPDevice.objects.get_or_create(user=request.user, name="default")
    if not device.key:
        device.generate_key()
        device.save()
    # We'll show a provisioning URI as QR
    uri = device.config_url
    return render(request, "accounts/otp_setup.html", {"uri": uri})


def otp_verify(request: HttpRequest) -> HttpResponse:
    user_id = request.session.get("otp_user_id")
    if not user_id:
        return redirect("accounts:login")

    form = TOTPForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        User = get_user_model()
        try:
            user = User.objects.get(pk=user_id)
            device = TOTPDevice.objects.filter(user=user, confirmed=True).first()
            if device and device.verify_token(form.cleaned_data["token"]):
                # Successful 2FA, attach device to session
                from django_otp import login as otp_login
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




from django.shortcuts import render, redirect
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.conf import settings

from .forms import JobSeekerSignupForm
from .tokens import account_activation_token


from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.shortcuts import render, redirect
from django.contrib import messages
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .tokens import account_activation_token
from .forms import JobSeekerSignupForm
from .email_threading import send_async_email

# views.py
@redirect_authenticated_user
def jobseeker_signup(request):
    if request.method == "POST":
        print("POST data:", request.POST)
        print("FILES data:", request.FILES)
        form = JobSeekerSignupForm(request.POST, request.FILES)
        if form.is_valid():
            user = form.save(commit=True)

            # Prepare activation email
            current_site = get_current_site(request)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = account_activation_token.make_token(user)
            activation_link = request.build_absolute_uri(
                reverse("accounts:activate", kwargs={"uidb64": uid, "token": token})
            )

            # Email context
            context = {
                'first_name': user.first_name,
                'activation_link': activation_link,
                'user': user,
            }

            # Send email asynchronously using threading
            try:
                send_async_email(
                    subject="Verify Your Email Address - Complete Your Registration",
                    template_name='accounts/email/email_verification.html',
                    context=context,
                    to_email=user.email
                )
                
                messages.success(request, "Registration successful! Please check your email to verify your account.")
                return render(request, "accounts/email/email_verification_sent.html", {
                    'user': user
                })
                
            except Exception as e:
                # Log the error but don't fail the registration
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Email sending error: {e}")
                
                messages.warning(request, "Account created successfully! However, we encountered an issue sending the verification email. Please contact support.")
                return render(request, "accounts/email/email_verification_sent.html", {
                    'user': user
                })
        else:
            # Debug: Print form errors to console
            print("Form errors:", form.errors)
            messages.error(request, "Please correct the errors below.")

    else:
        form = JobSeekerSignupForm()

    return render(request, "accounts/signup.html", {"form": form})



from django.contrib.auth import get_user_model

User = get_user_model()



def resend_activation(request):
    if request.method == "POST":
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email, is_active=False)
            
            # Generate new activation link
            current_site = get_current_site(request)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = account_activation_token.make_token(user)
            activation_link = request.build_absolute_uri(
                reverse("accounts:activate", kwargs={"uidb64": uid, "token": token})
            )

            # Send new activation email
            context = {
                'first_name': user.first_name,
                'activation_link': activation_link,
                'user': user,
            }

            send_async_email(
                subject="Verify Your Email Address - New Activation Link",
                template_name='accounts/email/email_verification.html',
                context=context,
                to_email=user.email
            )
            
            messages.success(request, "A new activation link has been sent to your email.")
            return render(request, "accounts/email/email_verification_sent.html", {
                'user': user
            })
            
        except User.DoesNotExist:
            messages.error(request, "No inactive account found with this email address.")
    
    return render(request, 'accounts/resend_activation.html')

def resend_activation_for_user(request, user_id):
    """Resend activation for a specific user (used in activation failed page)"""
    try:
        user = User.objects.get(pk=user_id, is_active=False)
        
        # Generate new activation link
        current_site = get_current_site(request)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = account_activation_token.make_token(user)
        activation_link = request.build_absolute_uri(
            reverse("accounts:activate", kwargs={"uidb64": uid, "token": token})
        )

        # Send new activation email
        context = {
            'first_name': user.first_name,
            'activation_link': activation_link,
            'user': user,
        }

        send_async_email(
            subject="Verify Your Email Address - New Activation Link",
            template_name='accounts/email/email_verification.html',
            context=context,
            to_email=user.email
        )
        
        messages.success(request, "A new activation link has been sent to your email.")
        return redirect('accounts:activation_sent')
        
    except User.DoesNotExist:
        messages.error(request, "User not found or account is already active.")
        return redirect('accounts:login')



def send_verification_email(request, user):
    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
    token = account_activation_token.make_token(user)
    activation_path = reverse('accounts:activate', kwargs={'uidb64': uidb64, 'token': token})
    activation_link = request.build_absolute_uri(activation_path)

    subject = "Activate your account"
    context = {"user": user, "activation_link": activation_link}

    text_message = render_to_string("accounts/email/activation_email.txt", context)
    html_message = render_to_string("accounts/email/activation_email.html", context)

    email = EmailMultiAlternatives(
        subject, text_message,
        getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@example.com"),
        [user.email],
    )
    email.attach_alternative(html_message, "text/html")
    email.send()


def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user and account_activation_token.check_token(user, token):
        user.is_active = True
        user.email_verified = True
        user.save()
        # login(request, user)
        return render(request, "accounts/activation_success.html", {"user": user})
    else:
        return render(request, "accounts/activation_failed.html")


# Resend Activation
from django import forms

class ResendActivationForm(forms.Form):
    email = forms.EmailField(label="Email", max_length=254)

RATE_LIMIT_SECONDS = 60

def resend_activation(request):
    if request.method == "POST":
        form = ResendActivationForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data["email"].lower()
            cache_key = f"resend_activation_{email}"
            last_sent = cache.get(cache_key)
            now = time.time()

            if last_sent and now - last_sent < RATE_LIMIT_SECONDS:
                wait_time = int(RATE_LIMIT_SECONDS - (now - last_sent))
                messages.error(request, f"Please wait {wait_time} seconds before requesting another activation email.")
                return redirect("accounts:resend_activation")

            try:
                user = User.objects.get(email__iexact=email)
            except User.DoesNotExist:
                messages.success(request, "If an account exists for this email, an activation link has been sent.")
                return redirect("accounts:login")

            if user.is_active:
                messages.info(request, "This account is already active. You can log in.")
                return redirect("accounts:login")

            send_verification_email(request, user)
            cache.set(cache_key, now, RATE_LIMIT_SECONDS)
            messages.success(request, "Activation email resent. Check your inbox.")
            return redirect("accounts:login")
    else:
        form = ResendActivationForm()

    return render(request, "accounts/resend_activation.html", {"form": form})


from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction

import logging
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .models import JobSeekerProfile

logger = logging.getLogger(__name__)

@login_required
def jobseeker_dashboard(request):
    """
    Simplified optimized dashboard.
    """
    try:
        profile = JobSeekerProfile.objects.filter(user=request.user).first()
        
        context = {
            "user_first_name": request.user.first_name,
            "user_full_name": f"{request.user.first_name} {request.user.last_name}".strip(),
            "user_email": request.user.email,
            "profile": profile,
        }
        
        if not profile:
            messages.info(request, "Complete your profile to unlock all features.")
        
        return render(request, "job_seeker_templates/jobseeker_dashboard.html", context)
        
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        context = {
            "user_first_name": request.user.first_name,
            "user_email": request.user.email,
            "error": True,
        }
        return render(request, "job_seeker_templates/jobseeker_dashboard.html", context)


from django.contrib.auth.views import (
    PasswordResetView, 
    PasswordResetDoneView, 
    PasswordResetConfirmView, 
    PasswordResetCompleteView
)
from django.contrib import messages
from django.urls import reverse_lazy
from django.contrib.auth.views import PasswordResetView
from django.contrib import messages
from django.urls import reverse_lazy
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings
from django.contrib.auth.views import PasswordResetView
from django.contrib import messages
from django.urls import reverse_lazy
from django.template.loader import render_to_string
from .email_threading import send_async_email


class CustomPasswordResetView(PasswordResetView):
    """
    Custom Password Reset View with threaded email sending and HTML support
    """
    template_name = 'accounts/password_reset.html'
    email_template_name = 'accounts/email/password_reset_email.txt'
    html_email_template_name = 'accounts/email/password_reset_email.html'
    subject_template_name = 'accounts/email/password_reset_subject.txt'
    success_url = reverse_lazy('accounts:password_reset_done')

    def send_mail(
        self,
        subject_template_name,
        email_template_name,
        context,
        from_email,
        to_email,
        html_email_template_name=None
    ):
        """
        Override Django's default send_mail to send email asynchronously (threaded)
        and include HTML version.
        """
        try:
            # Render the subject
            subject = render_to_string(subject_template_name, context)
            subject = ''.join(subject.splitlines()).strip()

            # ✅ Prefer the provided HTML template if available
            html_template = html_email_template_name or self.html_email_template_name or email_template_name

            # Send asynchronously (threaded)
            send_async_email(
                subject=subject,
                template_name=html_template,
                context=context,
                to_email=to_email
            )

        except Exception as e:
            print(f"⚠️ Error in password reset email: {str(e)}")
            # Do not raise to avoid revealing user existence

    def form_valid(self, form):
        """
        Called when the form is valid — after email is sent (if user exists).
        """
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