import logging
import os
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse, JsonResponse, Http404
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from django.utils import timezone
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.views.generic import DetailView
from django.contrib.auth import logout

from accounts.forms import JobSeekerSignupForm, CustomPasswordChangeForm
from accounts.models import JobSeekerProfile, User
from accounts.decorators import redirect_authenticated_user, job_seeker_required
from accounts.utils import _send_activation_email
from job.models import Job, JobCategory, JobApplication, SavedJob
from job.forms import JobApplicationForm, SaveJobForm, JobSeekerProfileForm, ResumeUploadForm

logger = logging.getLogger(__name__)


def get_client_ip(request):
    """Get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def calculate_profile_completeness(profile):
    """Calculate how complete the profile is (0-100%)"""
    required_fields = [
        profile.user.first_name,
        profile.user.last_name, 
        profile.user.email,
        profile.location,
        profile.years_of_experience,
        profile.highest_education,
    ]
    
    # Count completed fields
    completed = sum(1 for field in required_fields if field)
    
    # Add points for optional fields
    optional_fields = [profile.phone, profile.key_skills, profile.cover_letter, profile.resume]
    completed += sum(0.25 for field in optional_fields if field)  # 0.25 points each
    
    # Calculate percentage (max 8 points = 100%)
    return min(100, int((completed / 6.5) * 100))


# Registration View
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


# Dashboard & Profile Views
@login_required
@job_seeker_required
def jobseeker_dashboard(request):
    """Simplified optimized dashboard."""
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


@login_required
@job_seeker_required
def profile_view(request):
    """Main profile view for job seekers"""
    try:
        profile = request.user.jobseeker_profile
    except JobSeekerProfile.DoesNotExist:
        profile = JobSeekerProfile.objects.create(user=request.user)
    
    # Calculate profile completeness
    completeness = calculate_profile_completeness(profile)
    
    context = {
        'profile': profile,
        'skills_list': profile.get_skills_list(),
        'profile_completeness': completeness,
    }
    return render(request, 'job_seeker_templates/jobseeker_profile.html', context)


@login_required
@job_seeker_required
def profile_edit(request):
    """Edit profile view"""
    profile = get_object_or_404(JobSeekerProfile, user=request.user)
    
    if request.method == 'POST':
        form = JobSeekerProfileForm(request.POST, request.FILES, instance=profile)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated successfully!')
            return redirect('profile_view')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = JobSeekerProfileForm(instance=profile)
    
    return render(request, 'job_seeker_templates/profile_edit.html', {'form': form})


@login_required
@job_seeker_required
def upload_resume(request):
    """AJAX resume upload"""
    if request.method == 'POST' and request.FILES:
        profile = get_object_or_404(JobSeekerProfile, user=request.user)
        form = ResumeUploadForm(request.POST, request.FILES, instance=profile)
        
        if form.is_valid():
            form.save()
            return JsonResponse({
                'success': True,
                'resume_url': profile.resume.url if profile.resume else None,
                'filename': profile.resume.name.split('/')[-1] if profile.resume else None
            })
        else:
            return JsonResponse({'success': False, 'errors': form.errors})
    
    return JsonResponse({'success': False, 'error': 'Invalid request'})


# Job Application Views
@require_http_methods(["GET", "POST"])
@csrf_protect
@login_required
@job_seeker_required
def apply_for_job(request, job_id):
    job = get_object_or_404(Job, id=job_id, status='publish')

    # Block expired jobs
    if job.is_expired():
        messages.error(request, "This job position has expired and is no longer accepting applications.")
        return redirect('job_list')

    if request.method == "POST":
        form = JobApplicationForm(request.POST, request.FILES, job=job)
        if form.is_valid():
            application = form.save(commit=False)
            application.job = job
            application.applicant = request.user
            application.ip_address = get_client_ip(request)
            application.user_agent = request.META.get('HTTP_USER_AGENT', '')
            application.save()

            messages.success(request, "Your application has been submitted successfully.")
            return redirect("job_detail_frontend", job_id=job.id)
        else:
            print(form.errors.as_json())
            messages.error(request, "Please fix the errors below and try again.")
    else:
        initial_data = {
            "applicant_name": f"{request.user.first_name} {request.user.last_name}".strip(),
            "applicant_email": request.user.email,
        }
        form = JobApplicationForm(initial=initial_data, job=job)

    return render(request, "job_seeker_templates/apply_job.html", {"form": form, "job": job})


@login_required
@job_seeker_required
def application_confirmation(request, application_id):
    application = get_object_or_404(JobApplication, id=application_id, applicant=request.user)
    
    context = {
        'application': application,
        'job': application.job,
    }
    
    return render(request, 'application_confirmation.html', context)


@login_required
@job_seeker_required
def my_applications(request):
    applications = JobApplication.objects.filter(applicant=request.user).select_related('job')
    
    status_filter = request.GET.get('status')
    if status_filter:
        applications = applications.filter(status=status_filter)
    
    context = {
        'applications': applications,
        'status_filter': status_filter,
        'total_applications': applications.count(),
    }
    
    return render(request, 'job_seeker_templates/manage_applications.html', context)


@login_required
@job_seeker_required
def application_detail(request, application_id):
    application = get_object_or_404(JobApplication, id=application_id, applicant=request.user)
    
    context = {
        'application': application,
        'job': application.job,
    }
    
    return render(request, 'job_seeker_templates/application_detail.html', context)


@login_required
@job_seeker_required
def check_application_status(request, job_id):
    job = get_object_or_404(Job, id=job_id)
    
    application = JobApplication.objects.filter(
        job=job, 
        applicant=request.user
    ).first()
    
    if application:
        return JsonResponse({
            'has_applied': True,
            'status': application.status,
            'applied_date': application.applied_at.strftime('%B %d, %Y'),
            'status_display': application.get_status_display(),
        })
    
    return JsonResponse({'has_applied': False})


@require_http_methods(["POST"])
@login_required
@job_seeker_required
@csrf_protect
def quick_apply(request, job_id):
    job = get_object_or_404(Job, id=job_id, status='publish')
    
    if job.is_expired():
        return JsonResponse({'success': False, 'error': 'Job has expired'})
    
    if JobApplication.objects.filter(job=job, applicant=request.user).exists():
        return JsonResponse({'success': False, 'error': 'Already applied'})
    
    application = JobApplication(
        job=job,
        applicant=request.user,
        applicant_name=f"{request.user.first_name} {request.user.last_name}".strip(),
        applicant_email=request.user.email,
        cover_letter=f"I am interested in the {job.title} position at {job.location}.",
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
    )
    application.save()
    
    return JsonResponse({'success': True, 'application_id': application.id})


# Saved Jobs Views
@require_http_methods(["POST"])
@csrf_protect
@login_required
@job_seeker_required
def save_job(request, job_id):
    """Save/Bookmark a job for the authenticated job seeker"""
    job = get_object_or_404(Job, id=job_id, status='publish')
    
    # Check if job is already saved
    if SavedJob.objects.filter(job_seeker=request.user, job=job).exists():
        return JsonResponse({
            'success': False,
            'error': 'Job is already in your saved list.'
        })
    
    # Handle form data for advanced saving
    form = SaveJobForm(request.POST)
    
    if form.is_valid():
        saved_job = form.save(commit=False)
        saved_job.job_seeker = request.user
        saved_job.job = job
        saved_job.save()
        
        return JsonResponse({
            'success': True,
            'message': 'Job saved successfully!',
            'saved_job_id': saved_job.id,
            'action': 'saved'
        })
    else:
        # Simple save without additional data
        saved_job = SavedJob.objects.create(
            job_seeker=request.user,
            job=job
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Job saved successfully!',
            'saved_job_id': saved_job.id,
            'action': 'saved'
        })


@require_http_methods(["POST"])
@csrf_protect
@login_required
@job_seeker_required
def unsave_job(request, job_id):
    """Remove a job from saved list"""
    job = get_object_or_404(Job, id=job_id)
    
    try:
        saved_job = SavedJob.objects.get(job_seeker=request.user, job=job)
        saved_job.delete()
        
        return JsonResponse({
            'success': True,
            'message': 'Job removed from saved list.',
            'action': 'unsaved'
        })
    except SavedJob.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Job not found in your saved list.'
        })


@require_http_methods(["POST"])
@csrf_protect
@login_required
@job_seeker_required
def toggle_save_job(request, job_id):
    """Toggle save/unsave job (single endpoint for both actions)"""
    job = get_object_or_404(Job, id=job_id, status='publish')
    
    # Check if job is already saved
    saved_job = SavedJob.objects.filter(job_seeker=request.user, job=job).first()
    
    if saved_job:
        # Unsave the job
        saved_job.delete()
        return JsonResponse({
            'success': True,
            'message': 'Job removed from saved list.',
            'action': 'unsaved',
            'is_saved': False
        })
    else:
        # Save the job
        saved_job = SavedJob.objects.create(job_seeker=request.user, job=job)
        return JsonResponse({
            'success': True,
            'message': 'Job saved successfully!',
            'action': 'saved',
            'is_saved': True,
            'saved_job_id': saved_job.id
        })


@login_required
@job_seeker_required
def saved_jobs_list(request):
    """Display all saved jobs for the current job seeker"""
    # Get saved jobs with related job data
    saved_jobs = SavedJob.objects.filter(job_seeker=request.user).select_related('job')
    
    # Filter by category if provided
    category_filter = request.GET.get('category')
    if category_filter:
        saved_jobs = saved_jobs.filter(category=category_filter)
    
    # Group by category for sidebar
    categories = SavedJob.CATEGORY_CHOICES
    category_counts = {}
    for category_code, category_name in categories:
        category_counts[category_code] = SavedJob.objects.filter(
            job_seeker=request.user,
            category=category_code
        ).count()
    
    context = {
        'saved_jobs': saved_jobs,
        'category_filter': category_filter,
        'categories': categories,
        'category_counts': category_counts,
        'total_saved': saved_jobs.count(),
    }
    
    return render(request, 'job_seeker_templates/bookmarked_jobs.html', context)


@require_http_methods(["POST"])
@csrf_protect
@login_required
@job_seeker_required
def update_saved_job(request, saved_job_id):
    """Update saved job details (category, notes, reminder)"""
    saved_job = get_object_or_404(SavedJob, id=saved_job_id, job_seeker=request.user)
    
    form = SaveJobForm(request.POST, instance=saved_job)
    if form.is_valid():
        form.save()
        return JsonResponse({
            'success': True,
            'message': 'Saved job updated successfully!'
        })
    else:
        return JsonResponse({
            'success': False,
            'error': 'Invalid form data.'
        })


@login_required
@job_seeker_required
def check_job_saved(request, job_id):
    """Check if a job is saved by the current user"""
    job = get_object_or_404(Job, id=job_id)
    is_saved = SavedJob.objects.filter(job_seeker=request.user, job=job).exists()
    
    return JsonResponse({
        'is_saved': is_saved,
        'job_id': job_id
    })


# Public Profile View
class PublicProfileView(DetailView):
    """Public profile view for employers"""
    model = JobSeekerProfile
    template_name = 'job_seeker_templates/public_profile.html'
    context_object_name = 'profile'
    
    def get_queryset(self):
        return JobSeekerProfile.objects.select_related('user').filter(
            user__is_active=True
        )
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['skills_list'] = self.object.get_skills_list()
        return context
    
    

# @login_required
# @job_seeker_required
# def jobseeker_change_password(request):
#     """Password change page for job seekers with automatic logout after success"""
#     if request.method == 'POST':
#         form = CustomPasswordChangeForm(request.user, request.POST)
#         if form.is_valid():
#             user = form.save()
#             # Logout the user after password change for security
#             logout(request)
#             messages.success(
#                 request, 
#                 'Your password has been changed successfully! Please log in again with your new password.'
#             )
#             return redirect('accounts:login')
#         else:
#             messages.error(request, 'Please correct the errors below.')
#     else:
#         form = CustomPasswordChangeForm(request.user)
    
#     return render(request, 'job_seeker_templates/change_password.html', {
#         'form': form,
#         'active_tab': 'password'
#     })


# accounts/views/jobseeker_views.py
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.template.loader import render_to_string
from accounts.forms import CustomPasswordChangeForm
from accounts.decorators import job_seeker_required
from accounts.email_threading import send_async_email  # If you have async email setup

@login_required
@job_seeker_required
def jobseeker_change_password(request):
    """Password change page for job seekers with security notification"""
    if request.method == 'POST':
        form = CustomPasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            
            # Send security notification email
            send_password_change_notification(request, user)
            
            # Logout the user after password change for security
            logout(request)
            messages.success(
                request, 
                'Your password has been changed successfully! Please log in again with your new password. A security notification has been sent to your email.'
            )
            return redirect('accounts:login')
        else:
            # Add form errors to messages for display in template
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = CustomPasswordChangeForm(request.user)
    
    return render(request, 'job_seeker_templates/change_password.html', {
        'form': form,
        'active_tab': 'password'
    })


def send_password_change_notification(request, user):
    """Send security notification email when password is changed"""
    try:
        # Get client IP and user agent for security info
        client_ip = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')
        
        # Prepare email context
        context = {
            'user': user,
            'timestamp': timezone.now(),
            'ip_address': client_ip,
            'user_agent': user_agent[:100],  # Limit length
            'browser_info': get_browser_info(user_agent),
            'admin_contact_email': getattr(settings, 'ADMIN_EMAIL', 'info@techrecruitmentuk.com'),
            'support_phone': getattr(settings, 'SUPPORT_PHONE', '+1-555-0123'),
            'company_name': getattr(settings, 'COMPANY_NAME', 'Our Company'),
        }
        
        # Render email templates
        subject = "Security Alert: Your Password Has Been Changed"
        html_message = render_to_string('accounts/email/password_change_notification.html', context)
        text_message = render_to_string('accounts/email/password_change_notification.txt', context)
        
        # Send email (use async if available, otherwise sync)
        try:
            # Try async first
            send_async_email(
                subject=subject,
                template_name='accounts/email/password_change_notification.html',
                context=context,
                to_email=user.email
            )
        except:
            # Fallback to synchronous email
            send_mail(
                subject=subject,
                message=text_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                html_message=html_message,
                fail_silently=False,
            )
            
    except Exception as e:
        # Log the error but don't break the password change process
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Failed to send password change notification to {user.email}: {e}")


def get_client_ip(request):
    """Extract client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def get_browser_info(user_agent):
    """Extract browser information from user agent"""
    if 'Chrome' in user_agent:
        return 'Chrome'
    elif 'Firefox' in user_agent:
        return 'Firefox'
    elif 'Safari' in user_agent:
        return 'Safari'
    elif 'Edge' in user_agent:
        return 'Edge'
    elif 'Opera' in user_agent:
        return 'Opera'
    else:
        return 'Unknown Browser'