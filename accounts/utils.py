import time
import logging
import base64
import qrcode
import pyotp
from io import BytesIO

from django.core.cache import cache
from django.core.signing import Signer, BadSignature
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.urls import reverse
from django.http import HttpResponse
from django.conf import settings

from .tokens import account_activation_token
from .email_threading import send_async_email
from django_otp.plugins.otp_totp.models import TOTPDevice

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
        secure=not settings.DEBUG,
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

def verify_otp_with_tolerance(user, otp_token, tolerance=2):
    """
    Verify OTP token with time drift tolerance
    tolerance=2 means current step, two steps before, and two steps after
    """
    devices = TOTPDevice.objects.devices_for_user(user)
    
    print(f"Checking {len(devices)} devices for user {user.email}")
    
    for device in devices:
        print(f"Checking device: {device.name} (confirmed: {device.confirmed})")
        
        # Try current time with device's verify_token first
        if device.verify_token(otp_token):
            print("Standard device verification SUCCESS")
            return True, device
        
        # If that fails, try with pyotp and tolerance
        if tolerance > 0 and device.bin_key:
            try:
                # Convert binary key to base32 for pyotp
                secret_key = base64.b32encode(device.bin_key).decode('utf-8')
                
                # Create TOTP instance with base32 secret
                totp = pyotp.TOTP(secret_key)
                
                # Get current time
                current_time = time.time()
                
                print(f"Trying tolerance check with secret (base32): {secret_key}")
                
                # Check previous and next time steps
                for t in range(-tolerance, tolerance + 1):
                    if t == 0:
                        continue  # Skip 0 as we already tried it
                    
                    try:
                        # Generate token for this time step
                        expected_token = totp.at(current_time + (t * 30))  # 30 seconds per step
                        print(f"Tolerance {t}: Expected token {expected_token}, Got {otp_token}")
                        
                        if str(otp_token) == str(expected_token):
                            print(f"Tolerance verification SUCCESS at offset {t}")
                            return True, device
                    except Exception as e:
                        print(f"Error in tolerance check {t}: {e}")
                        continue
            except Exception as e:
                print(f"Error in tolerance verification: {e}")
                continue
    
    print("All verification attempts failed")
    return False, None

def get_current_otp(bin_key):
    """Get current OTP for debugging - accepts binary key"""
    try:
        # Convert binary key to base32
        secret_key = base64.b32encode(bin_key).decode('utf-8')
        totp = pyotp.TOTP(secret_key)
        return totp.now()
    except Exception as e:
        print(f"Error getting current OTP: {e}")
        return None

def debug_otp_tokens(bin_key, steps=2):
    """Debug function to show current and surrounding OTP tokens - accepts binary key"""
    try:
        # Convert binary key to base32
        secret_key = base64.b32encode(bin_key).decode('utf-8')
        totp = pyotp.TOTP(secret_key)
        current_time = time.time()
        
        tokens = {}
        for i in range(-steps, steps + 1):
            time_step = current_time + (i * 30)
            token = totp.at(time_step)
            tokens[i] = {
                'token': token,
                'time_offset': i * 30
            }
        
        return tokens
    except Exception as e:
        print(f"Error in debug_otp_tokens: {e}")
        return {}

def generate_qr_code(provisioning_uri):
    """Generate QR code for OTP setup"""
    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        return base64.b64encode(buffer.getvalue()).decode()
    except Exception as e:
        logger.error(f"Error generating QR code: {e}")
        return ""

def get_secret_key_hex(bin_key):
    """Convert binary key to hex string for display"""
    return bin_key.hex() if bin_key else ""

def get_secret_key_base32(bin_key):
    """Convert binary key to base32 for authenticator apps"""
    return base64.b32encode(bin_key).decode('utf-8') if bin_key else ""