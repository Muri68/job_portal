from functools import wraps
from django.http import HttpResponseRedirect
from django.conf import settings
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.contrib import messages
from django.shortcuts import redirect

def redirect_authenticated_user(view_func):
    """
    Redirect authenticated users away from auth pages (login/signup).
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if request.user.is_authenticated:
            # Get the 'next' parameter from GET or POST
            next_url = request.POST.get('next') or request.GET.get('next')
            
            # Check if the 'next' URL is safe to redirect to
            if next_url and url_has_allowed_host_and_scheme(
                url=next_url, 
                allowed_hosts={request.get_host()},
                require_https=request.is_secure()
            ):
                return HttpResponseRedirect(next_url)
            
            # Try to get the HTTP_REFERER (previous page)
            referer = request.META.get('HTTP_REFERER')
            if referer and url_has_allowed_host_and_scheme(
                url=referer,
                allowed_hosts={request.get_host()},
                require_https=request.is_secure()
            ):
                # Avoid redirecting back to auth pages to prevent loops
                auth_urls = [
                    reverse('accounts:login'),
                    reverse('accounts:jobseeker_signup'),
                    # Add other auth URLs as needed
                ]
                
                # Check if referer contains any auth URL
                if not any(auth_url in referer for auth_url in auth_urls):
                    return HttpResponseRedirect(referer)
            
            # Fallback to the default redirect URL
            return HttpResponseRedirect(settings.LOGIN_REDIRECT_URL)
        
        return view_func(request, *args, **kwargs)
    return _wrapped_view

def job_seeker_required(view_func):
    """
    Decorator that checks if the user is authenticated and has the Job Seeker role.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            messages.warning(request, "Please log in as a Job Seeker to access this page.")
            login_url = reverse('accounts:login')
            # Use request.build_absolute_uri() for the full path
            next_url = request.build_absolute_uri()
            redirect_url = f"{login_url}?next={next_url}"
            return redirect(redirect_url)
        
        # Check if user has job seeker role (uncomment and modify based on your user model)
        if not hasattr(request.user, 'role') or request.user.role != 'job_seeker':
        # Alternative: if you have a method like is_job_seeker()
        # if not request.user.is_job_seeker():
            messages.error(request, "Access denied. This feature is only available for Job Seekers.")
            return redirect('index')  # or redirect to job seeker dashboard
        
        return view_func(request, *args, **kwargs)
    return _wrapped_view

def employer_required(view_func):
    """
    Decorator that checks if the user is authenticated and has the Employer role.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            messages.warning(request, "Please log in as an Employer to access this page.")
            login_url = reverse('accounts:login')
            next_url = request.build_absolute_uri()
            redirect_url = f"{login_url}?next={next_url}"
            return redirect(redirect_url)
        
        # Check if user has employer role
        if not hasattr(request.user, 'role') or request.user.role != 'employer':
        # Alternative: if you have a method like is_employer()
        # if not request.user.is_employer():
            messages.error(request, "Access denied. This feature is only available for Employers.")
            return redirect('index')  # or redirect to employer dashboard
        
        return view_func(request, *args, **kwargs)
    return _wrapped_view



def admin_required(view_func):
    """
    Decorator that checks if the user is authenticated and has Admin privileges.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            messages.warning(request, "Please log in to access this page.")
            login_url = reverse('accounts:login')
            next_url = request.build_absolute_uri()
            redirect_url = f"{login_url}?next={next_url}"
            return redirect(redirect_url)
        
        # Check if user is admin (using Django's built-in is_staff or your custom field)
        if not request.user.is_staff:
        # Alternative: if you have a custom field like is_site_admin
        # if not request.user.is_site_admin:
            messages.error(request, "Access denied. Admin privileges required.")
            return redirect('index')
        
        return view_func(request, *args, **kwargs)
    return _wrapped_view

# More specific decorators that combine authentication and role checks
def role_required(allowed_roles):
    """
    Decorator that checks if user has one of the allowed roles.
    Usage: @role_required(['job_seeker', 'employer'])
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                messages.warning(request, "Please log in to access this page.")
                login_url = reverse('accounts:login')
                next_url = request.build_absolute_uri()
                redirect_url = f"{login_url}?next={next_url}"
                return redirect(redirect_url)
            
            # Check if user has one of the allowed roles
            user_role = getattr(request.user, 'role', None)
            if user_role not in allowed_roles:
                messages.error(request, f"Access denied. Required roles: {', '.join(allowed_roles)}")
                return redirect('index')
            
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator