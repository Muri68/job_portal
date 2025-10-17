import json
import logging
import threading
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from django.core.paginator import Paginator
from django.db import models
from django.db.models import Count, Q
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.mail import EmailMessage
from django.conf import settings

from accounts.forms import AdminUserCreationForm, UserProfileForm, CustomPasswordChangeForm
from accounts.models import User
from accounts.decorators import admin_required
from job.models import Job, JobCategory, JobApplication
from job.forms import JobForm

logger = logging.getLogger(__name__)


class EmailThread(threading.Thread):
    """Thread for sending emails in background"""
    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        try:
            self.email.send()
        except Exception as e:
            print(f"Failed to send email: {e}")


def send_email_in_background(email):
    """Helper function to send email in background"""
    EmailThread(email).start()


# Dashboard View
# Dashboard View
@login_required
@admin_required
def admin_dashboard(request):
    page_title = 'Dashboard'

    # Job statistics
    total_jobs = Job.objects.count()
    total_admins = User.objects.filter(
            Q(role=User.Role.SITE_ADMIN) | Q(is_superuser=True)
        ).count()

    # Application statistics
    total_applications = JobApplication.objects.count()

    # Recent activity
    recent_jobs = Job.objects.order_by('-created_at')[:5]
    recent_applications = JobApplication.objects.select_related('job').order_by('-applied_at')[:5]

    # Top 5 most applied jobs
    from django.db.models import Count
    top_jobs = Job.objects.annotate(
        application_count=Count('applications')
    ).order_by('-application_count')[:5]

    # Prepare chart data - handle empty data case
    top_job_titles = []
    top_job_applications = []
    
    for job in top_jobs:
        # Truncate long job titles for better display
        title = job.title
        if len(title) > 30:
            title = title[:27] + '...'
        top_job_titles.append(title)
        top_job_applications.append(job.application_count)

    # If no applications yet, show placeholder data
    if not top_job_applications:
        top_job_titles = ['No applications yet']
        top_job_applications = [0]

    context = {
        'page_title': page_title,
        'total_jobs': total_jobs,
        'total_admins': total_admins,
        'total_applications': total_applications,
        'recent_jobs': recent_jobs,
        'recent_applications': recent_applications,
        'top_job_titles': top_job_titles,
        'top_job_applications': top_job_applications,
    }
    return render(request, 'job/dashboard.html', context)


@login_required
@admin_required
def add_admin_user(request):
    """View to add new admin users"""
    if request.method == 'POST':
        form = AdminUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            
            if form.cleaned_data.get('send_welcome_email'):
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
    """List all admin users with enhanced functionality"""
    admin_users = User.objects.filter(
        models.Q(role=User.Role.SITE_ADMIN) | models.Q(is_superuser=True)
    ).order_by('-date_joined')
    
    paginator = Paginator(admin_users, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    return render(request, 'job/admin_users_list.html', {
        'page_obj': page_obj,
        'active_superusers_count': User.get_active_superusers_count()
    })


@login_required
@admin_required
def toggle_admin_status(request, user_id):
    """Activate/Deactivate admin user with comprehensive protection"""
    admin_user = get_object_or_404(User, id=user_id)
    
    if admin_user == request.user:
        messages.error(request, "You cannot modify your own account status.")
        return redirect('admin_users_list')
    
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
@admin_required
def delete_admin_user(request, user_id):
    """Delete admin user with comprehensive protection"""
    admin_user = get_object_or_404(User, id=user_id)
    
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
def admin_change_password(request):
    """Password change page with automatic logout after success"""
    if request.method == 'POST':
        form = CustomPasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            logout(request)
            messages.success(
                request, 
                'Your password has been changed successfully! Please log in again with your new password.'
            )
            return redirect('accounts:login')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = CustomPasswordChangeForm(request.user)
    
    return render(request, 'job/change_password.html', {
        'form': form,
        'active_tab': 'password'
    })


@login_required
@admin_required
def admin_settings(request):
    """Main settings page that redirects to profile or password"""
    return redirect('user_profile')


@login_required
@admin_required
def job_list(request):
    # Get filter parameters
    status_filter = request.GET.get('status', '')
    category_filter = request.GET.get('category', '')
    search_query = request.GET.get('q', '')
    
    # Start with all jobs and annotate with application counts
    jobs = Job.objects.annotate(
        applications_count=Count('applications')
    ).select_related('category').prefetch_related('applications')
    
    # Apply filters
    if status_filter:
        jobs = jobs.filter(status=status_filter)
    if category_filter:
        jobs = jobs.filter(category_id=category_filter)
    if search_query:
        jobs = jobs.filter(
            Q(title__icontains=search_query) |
            Q(description__icontains=search_query) |
            Q(location__icontains=search_query)
        )
    
    # Order by most recent first
    jobs = jobs.order_by('-created_at')
    
    # Pagination
    paginator = Paginator(jobs, 10)  # Show 10 jobs per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    categories = JobCategory.objects.all()
    
    context = {
        'page_obj': page_obj,
        'categories': categories,
        'status_filter': status_filter,
        'category_filter': category_filter,
        'search_query': search_query,
    }
    
    return render(request, 'job/job_list.html', context)


@login_required
@admin_required
def job_manage(request, job_id=None):
    # Get job instance if editing
    job = None
    if job_id:
        job = get_object_or_404(Job, id=job_id)
    
    categories = JobCategory.objects.all()
    
    if request.method == 'POST':
        form = JobForm(request.POST, instance=job)
        if form.is_valid():
            form.save()
            action = "updated" if job else "created"
            messages.success(request, f'Job {action} successfully!')
            return redirect('job_list')
    else:
        form = JobForm(instance=job)
    
    context = {
        'form': form,
        'job': job,
        'categories': categories,
    }
    
    return render(request, 'job/job_manage.html', context)


@login_required
@admin_required
def job_detail(request, job_id):
    job = get_object_or_404(Job, id=job_id)
    return render(request, 'job/job_detail.html', {'job': job})


@login_required
@admin_required
def job_delete(request, job_id):
    """
    Delete a job
    """
    job = get_object_or_404(Job, id=job_id)
    
    if request.method == 'POST':
        job_title = job.title
        job.delete()
        
        messages.success(request, f'Job "{job_title}" has been deleted successfully!')
        return redirect('job_list')
    
    # If GET request, show the job list page (the modal will handle the confirmation)
    return redirect('job_list')


@login_required
@admin_required
def job_applications(request, job_id):
    """
    View applications for a specific job
    """
    job = get_object_or_404(Job, id=job_id)
    applications = JobApplication.objects.filter(job=job).order_by('-applied_at')
    
    # Status filter
    status_filter = request.GET.get('status', 'all')
    if status_filter != 'all':
        applications = applications.filter(status=status_filter)
    
    # Status choices for template
    status_choices = JobApplication.STATUS_CHOICES
    
    # Calculate status counts
    status_counts = {
        'total': applications.count(),
        'pending': applications.filter(status='pending').count(),
        'reviewed': applications.filter(status='reviewed').count(),
        'shortlisted': applications.filter(status='shortlisted').count(),
        'accepted': applications.filter(status='accepted').count(),
        'rejected': applications.filter(status='rejected').count(),
    }
    
    context = {
        'job': job,
        'applications': applications,
        'status_filter': status_filter,
        'status_choices': status_choices,
        'status_counts': status_counts,
    }
    return render(request, 'job/job_applications.html', context)


@login_required
@admin_required
@csrf_exempt  # Temporarily add this for debugging, remove in production
def update_application_status(request, application_id):
    """
    Update application status (AJAX view)
    """
    logger.info(f"Update status request for application {application_id}")
    
    # Check if it's an AJAX request
    if request.method != 'POST':
        logger.warning("Invalid request method: %s", request.method)
        return JsonResponse({
            'success': False, 
            'error': 'Only POST requests are allowed'
        }, status=405)
    
    # Check if it's an AJAX request (modern approach)
    if request.headers.get('X-Requested-With') != 'XMLHttpRequest':
        logger.warning("Not an AJAX request")
        return JsonResponse({
            'success': False, 
            'error': 'This endpoint only accepts AJAX requests'
        }, status=400)
    
    try:
        application = get_object_or_404(JobApplication, id=application_id)
        logger.info(f"Found application: {application}")
        
        # Parse the request data
        if request.content_type == 'application/json':
            try:
                data = json.loads(request.body)
                new_status = data.get('status')
                logger.info(f"JSON data received: {data}")
            except json.JSONDecodeError:
                logger.error("Invalid JSON data")
                return JsonResponse({
                    'success': False, 
                    'error': 'Invalid JSON data'
                }, status=400)
        else:
            new_status = request.POST.get('status')
            logger.info(f"Form data received, status: {new_status}")
        
        # Validate the status
        valid_statuses = dict(JobApplication.STATUS_CHOICES)
        if new_status not in valid_statuses:
            logger.error(f"Invalid status value: {new_status}")
            return JsonResponse({
                'success': False, 
                'error': f'Invalid status value. Must be one of: {", ".join(valid_statuses.keys())}'
            }, status=400)
        
        # Update the application
        application.status = new_status
        application.save()
        logger.info(f"Application status updated to: {new_status}")
        
        return JsonResponse({
            'success': True,
            'status': application.status,
            'status_display': application.get_status_display(),
            'message': 'Application status updated successfully.'
        })
        
    except JobApplication.DoesNotExist:
        logger.error(f"Application not found: {application_id}")
        return JsonResponse({
            'success': False, 
            'error': 'Application not found'
        }, status=404)
    except Exception as e:
        logger.exception("Unexpected error in update_application_status")
        return JsonResponse({
            'success': False, 
            'error': f'Server error: {str(e)}'
        }, status=500)


@login_required
@admin_required
def applicants_list(request):
    page_title = "Applicants"

    # Filtering (search by name, email, job title)
    query = request.GET.get('q', '')
    applications = JobApplication.objects.select_related('job').all()

    if query:
        applications = applications.filter(
            Q(applicant_name__icontains=query) |
            Q(applicant_email__icontains=query) |
            Q(job__title__icontains=query)
        )

    # Pagination
    paginator = Paginator(applications, 10)  # 10 per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_title': page_title,
        'applications': page_obj,
        'query': query,
    }
    return render(request, 'job/applicants.html', context)


@login_required
@admin_required
def applicant_detail(request, pk):
    page_title = "Applicant Profile"
    application = get_object_or_404(JobApplication.objects.select_related('job'), pk=pk)

    context = {
        'page_title': page_title,
        'application': application,
    }
    return render(request, 'job/applicant_detail.html', context)


@login_required
@admin_required
def compose_email(request, application_id):
    """Compose and send email to applicant"""
    application = get_object_or_404(JobApplication, id=application_id)
    
    if request.method == 'POST':
        subject = request.POST.get('subject', '').strip()
        message = request.POST.get('message', '').strip()
        email_type = request.POST.get('email_type', 'custom')
        attach_resume = request.POST.get('attach_resume') == 'on'
        
        # Validate required fields
        if not subject:
            messages.error(request, 'Email subject is required.')
            return redirect('compose_email', application_id=application.id)
        
        if not message:
            messages.error(request, 'Email message is required.')
            return redirect('compose_email', application_id=application.id)
        
        try:
            # Create email
            email = EmailMessage(
                subject=subject,
                body=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[application.applicant_email],
                reply_to=[settings.DEFAULT_FROM_EMAIL]
            )
            email.content_subtype = "html"
            
            # Attach resume if requested and available
            if attach_resume and application.resume:
                try:
                    email.attach_file(application.resume.path)
                except Exception as e:
                    print(f"Could not attach resume: {e}")
            
            # Send email in background
            send_email_in_background(email)
            
            messages.success(request, f'Email sent successfully to {application.applicant_name}!')
            return redirect('applicant_detail', pk=application.id)
            
        except Exception as e:
            messages.error(request, f'Failed to send email: {str(e)}')
    
    # Predefined email templates in plain text
    email_templates = {
        'interview_invite': {
            'subject': f'Interview Invitation - {application.job.title}',
            'message': f"""Dear {application.applicant_name},

    Thank you for your application for the {application.job.title} position at our company. We were impressed with your qualifications and experience.

    We would like to invite you for an interview to discuss your application further. Please let us know your availability for the upcoming week.

    Interview Details:
    - Position: {application.job.title}
    - Location: {application.job.location}
    - Type: {application.job.get_job_type_display()}

    Please confirm your availability by replying to this email.

    Best regards,
    {request.user.get_full_name() or request.user.email}
    Hiring Team
    {getattr(settings, 'COMPANY_NAME', 'Our Company')}"""
            },
            'application_received': {
                'subject': f'Application Received - {application.job.title}',
                'message': f"""Dear {application.applicant_name},

    Thank you for applying for the {application.job.title} position at our company. We have successfully received your application.

    Our hiring team will review your application carefully. If your qualifications match our requirements, we will contact you for the next steps in the hiring process.

    Application Details:
    - Position: {application.job.title}
    - Applied: {application.applied_at.strftime("%B %d, %Y")}
    - Reference ID: APP-{application.id:06d}

    We appreciate your interest in joining our team and will be in touch soon.

    Best regards,
    {request.user.get_full_name() or request.user.email}
    Hiring Team
    {getattr(settings, 'COMPANY_NAME', 'Our Company')}"""
            },
            'rejection': {
                'subject': f'Update on Your Application - {application.job.title}',
                'message': f"""Dear {application.applicant_name},

    Thank you for your interest in the {application.job.title} position at our company and for the time you invested in the application process.

    After careful consideration, we have decided to move forward with other candidates whose qualifications more closely match our current needs.

    We were impressed with your background and encourage you to apply for future positions that match your skills and experience. We will keep your application on file for future opportunities.

    We wish you the best in your job search and future professional endeavors.

    Best regards,
    {request.user.get_full_name() or request.user.email}
    Hiring Team
    {getattr(settings, 'COMPANY_NAME', 'Our Company')}"""
            }
    }
    
    context = {
        'application': application,
        'email_templates': email_templates,
        'default_subject': f'Regarding Your Application - {application.job.title}',
        'company_name': getattr(settings, 'COMPANY_NAME', 'Our Company')
    }
    
    return render(request, 'job/compose_email.html', context)




from django.views.generic import DetailView, ListView
from django.views.generic.edit import CreateView, UpdateView, DeleteView
from django.urls import reverse_lazy
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils.decorators import method_decorator
from django.contrib import messages
from django.shortcuts import render
from job.models import AboutUs, OurValue, TeamMember, CompanyStat
from job.forms import AboutUsForm, OurValueForm, TeamMemberForm, CompanyStatForm


# AboutUs Management Views
@method_decorator([login_required, admin_required], name='dispatch')
class AboutUsManageView(UpdateView):
    model = AboutUs
    form_class = AboutUsForm
    template_name = 'job/about/about_us_manage.html'
    success_url = reverse_lazy('about_manage')

    def get_object(self):
        about, created = AboutUs.objects.get_or_create(
            is_active=True,
            defaults={
                'title': 'About Our Company',
                'description': 'Tell your company story here...',
                'mission': 'Our mission statement...',
                'vision': 'Our vision statement...'
            }
        )
        return about

    def form_valid(self, form):
        messages.success(self.request, 'About Us content updated successfully!')
        return super().form_valid(form)

# OurValue Management Views
@method_decorator([login_required, admin_required], name='dispatch')
class OurValueListView(ListView):
    model = OurValue
    template_name = 'job/about/our_values_list.html'
    context_object_name = 'values'

    def get_queryset(self):
        return OurValue.objects.filter(is_active=True).order_by('order')

@method_decorator([login_required, admin_required], name='dispatch')
class OurValueCreateView(CreateView):
    model = OurValue
    form_class = OurValueForm
    template_name = 'job/about/our_value_form.html'
    success_url = reverse_lazy('our_values_list')

    def form_valid(self, form):
        messages.success(self.request, 'Value created successfully!')
        return super().form_valid(form)

@method_decorator([login_required, admin_required], name='dispatch')
class OurValueUpdateView(UpdateView):
    model = OurValue
    form_class = OurValueForm
    template_name = 'job/about/our_value_form.html'
    success_url = reverse_lazy('our_values_list')

    def form_valid(self, form):
        messages.success(self.request, 'Value updated successfully!')
        return super().form_valid(form)

@method_decorator([login_required, admin_required], name='dispatch')
class OurValueDeleteView(DeleteView):
    model = OurValue
    template_name = 'job/about/our_value_confirm_delete.html'
    success_url = reverse_lazy('our_values_list')

    def delete(self, request, *args, **kwargs):
        messages.success(self.request, 'Value deleted successfully!')
        return super().delete(request, *args, **kwargs)

# TeamMember Management Views
@method_decorator([login_required, admin_required], name='dispatch')
class TeamMemberListView(ListView):
    model = TeamMember
    template_name = 'job/about/team_members_list.html'
    context_object_name = 'team_members'

    def get_queryset(self):
        return TeamMember.objects.filter(is_active=True).order_by('order')

@method_decorator([login_required, admin_required], name='dispatch')
class TeamMemberCreateView(CreateView):
    model = TeamMember
    form_class = TeamMemberForm
    template_name = 'job/about/team_member_form.html'
    success_url = reverse_lazy('team_members_list')

    def form_valid(self, form):
        messages.success(self.request, 'Team member created successfully!')
        return super().form_valid(form)

@method_decorator([login_required, admin_required], name='dispatch')
class TeamMemberUpdateView(UpdateView):
    model = TeamMember
    form_class = TeamMemberForm
    template_name = 'job/about/team_member_form.html'
    success_url = reverse_lazy('team_members_list')

    def form_valid(self, form):
        messages.success(self.request, 'Team member updated successfully!')
        return super().form_valid(form)

@method_decorator([login_required, admin_required], name='dispatch')
class TeamMemberDeleteView(DeleteView):
    model = TeamMember
    template_name = 'job/about/team_member_confirm_delete.html'
    success_url = reverse_lazy('team_members_list')

    def delete(self, request, *args, **kwargs):
        messages.success(self.request, 'Team member deleted successfully!')
        return super().delete(request, *args, **kwargs)

# CompanyStat Management Views
@method_decorator([login_required, admin_required], name='dispatch')
class CompanyStatListView(ListView):
    model = CompanyStat
    template_name = 'job/about/company_stats_list.html'
    context_object_name = 'company_stats'

    def get_queryset(self):
        return CompanyStat.objects.filter(is_active=True).order_by('order')

@method_decorator([login_required, admin_required], name='dispatch')
class CompanyStatCreateView(CreateView):
    model = CompanyStat
    form_class = CompanyStatForm
    template_name = 'job/about/company_stat_form.html'
    success_url = reverse_lazy('company_stats_list')

    def form_valid(self, form):
        messages.success(self.request, 'Company stat created successfully!')
        return super().form_valid(form)

@method_decorator([login_required, admin_required], name='dispatch')
class CompanyStatUpdateView(UpdateView):
    model = CompanyStat
    form_class = CompanyStatForm
    template_name = 'job/about/company_stat_form.html'
    success_url = reverse_lazy('company_stats_list')

    def form_valid(self, form):
        messages.success(self.request, 'Company stat updated successfully!')
        return super().form_valid(form)

@method_decorator([login_required, admin_required], name='dispatch')
class CompanyStatDeleteView(DeleteView):
    model = CompanyStat
    template_name = 'job/about/company_stat_confirm_delete.html'
    success_url = reverse_lazy('company_stats_list')

    def delete(self, request, *args, **kwargs):
        messages.success(self.request, 'Company stat deleted successfully!')
        return super().delete(request, *args, **kwargs)
    
    
    
from django.views.generic import ListView, CreateView, UpdateView, DeleteView, TemplateView
from django.urls import reverse_lazy
from django.contrib import messages
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404
from job.models import ContactMessage, ContactInfo, FAQ, SiteSetting
from job.forms import ContactMessageForm, ContactInfoForm, FAQForm, SiteSettingForm


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

# Management Views
@method_decorator([login_required, admin_required], name='dispatch')
class ContactMessageListView(ListView):
    model = ContactMessage
    template_name = 'job/contact/contact_messages_list.html'
    context_object_name = 'messages'
    paginate_by = 20

    def get_queryset(self):
        return ContactMessage.objects.all().order_by('-created_at')

@method_decorator([login_required, admin_required], name='dispatch')
class ContactMessageDetailView(UpdateView):
    model = ContactMessage
    form_class = ContactMessageForm
    template_name = 'job/contact/contact_message_detail.html'
    success_url = reverse_lazy('contact_messages_list')

    def form_valid(self, form):
        messages.success(self.request, 'Message status updated successfully!')
        return super().form_valid(form)

@method_decorator([login_required, admin_required], name='dispatch')
class ContactMessageDeleteView(DeleteView):
    model = ContactMessage
    template_name = 'job/contact/contact_message_confirm_delete.html'
    success_url = reverse_lazy('contact_messages_list')

    def delete(self, request, *args, **kwargs):
        messages.success(self.request, 'Message deleted successfully!')
        return super().delete(request, *args, **kwargs)

@method_decorator([login_required, admin_required], name='dispatch')
class ContactInfoListView(ListView):
    model = ContactInfo
    template_name = 'job/contact/contact_info_list.html'
    context_object_name = 'contact_info'

    def get_queryset(self):
        return ContactInfo.objects.all().order_by('order')

@method_decorator([login_required, admin_required], name='dispatch')
class ContactInfoCreateView(CreateView):
    model = ContactInfo
    form_class = ContactInfoForm
    template_name = 'job/contact/contact_info_form.html'
    success_url = reverse_lazy('contact_info_list')

    def form_valid(self, form):
        messages.success(self.request, 'Contact information added successfully!')
        return super().form_valid(form)

@method_decorator([login_required, admin_required], name='dispatch')
class ContactInfoUpdateView(UpdateView):
    model = ContactInfo
    form_class = ContactInfoForm
    template_name = 'job/contact/contact_info_form.html'
    success_url = reverse_lazy('contact_info_list')

    def form_valid(self, form):
        messages.success(self.request, 'Contact information updated successfully!')
        return super().form_valid(form)

@method_decorator([login_required, admin_required], name='dispatch')
class ContactInfoDeleteView(DeleteView):
    model = ContactInfo
    template_name = 'job/contact/contact_info_confirm_delete.html'
    success_url = reverse_lazy('contact_info_list')

    def delete(self, request, *args, **kwargs):
        messages.success(self.request, 'Contact information deleted successfully!')
        return super().delete(request, *args, **kwargs)

@method_decorator([login_required, admin_required], name='dispatch')
class FAQListView(ListView):
    model = FAQ
    template_name = 'job/about/faq_list.html'
    context_object_name = 'faqs'

    def get_queryset(self):
        return FAQ.objects.all().order_by('order')

@method_decorator([login_required, admin_required], name='dispatch')
class FAQCreateView(CreateView):
    model = FAQ
    form_class = FAQForm
    template_name = 'job/about/faq_form.html'
    success_url = reverse_lazy('faq_list')

    def form_valid(self, form):
        messages.success(self.request, 'FAQ added successfully!')
        return super().form_valid(form)

@method_decorator([login_required, admin_required], name='dispatch')
class FAQUpdateView(UpdateView):
    model = FAQ
    form_class = FAQForm
    template_name = 'job/about/faq_form.html'
    success_url = reverse_lazy('faq_list')

    def form_valid(self, form):
        messages.success(self.request, 'FAQ updated successfully!')
        return super().form_valid(form)

@method_decorator([login_required, admin_required], name='dispatch')
class FAQDeleteView(DeleteView):
    model = FAQ
    template_name = 'job/about/faq_confirm_delete.html'
    success_url = reverse_lazy('faq_list')

    def delete(self, request, *args, **kwargs):
        messages.success(self.request, 'FAQ deleted successfully!')
        return super().delete(request, *args, **kwargs)

@method_decorator([login_required, admin_required], name='dispatch')
class SiteSettingUpdateView(UpdateView):
    model = SiteSetting
    form_class = SiteSettingForm
    template_name = 'job/site_setting_form.html'
    success_url = reverse_lazy('contact_settings')

    def get_object(self):
        setting, created = SiteSetting.objects.get_or_create()
        return setting

    def form_valid(self, form):
        messages.success(self.request, 'Site settings updated successfully!')
        return super().form_valid(form)