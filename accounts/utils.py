import time
import logging
from django.core.cache import cache
from django.core.signing import Signer, BadSignature
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.urls import reverse
from django.http import HttpResponse
from django.conf import settings

from .tokens import account_activation_token
from .email_threading import send_async_email

logger = logging.getLogger(__name__)
signer = Signer()

# Constants
TRUSTED_DEVICE_COOKIE = getattr(settings, 'TRUSTED_DEVICE_COOKIE', 'trusted_device')
TRUSTED_DEVICE_MAX_AGE = getattr(settings, 'TRUSTED_DEVICE_MAX_AGE', 30 * 24 * 60 * 60)

def _set_trusted_device(response: HttpResponse, user) -> None:
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

def _has_trusted_device(request, user) -> bool:
    """Check if user has a trusted device cookie."""
    cookie = request.COOKIES.get(TRUSTED_DEVICE_COOKIE)
    if not cookie:
        return False
    
    try:
        raw = signer.unsign(cookie)
        return raw == str(user.pk)
    except BadSignature:
        return False

def _send_activation_email(user, request, subject_suffix: str = "") -> None:
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