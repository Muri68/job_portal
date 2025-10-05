from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import Count, Q, Avg
from django.utils import timezone

from job.models import Job, JobCategory, JobApplication
from job.forms import JobForm, SaveJobForm
from accounts.models import User


# ---------------------------------------------------------------------------------------------------------------------
######################################## FRONTEND VIEWS
# ---------------------------------------------------------------------------------------------------------------------

def index(request):
    jobs = Job.objects.filter(status='publish')[:4]
    
    # Get all categories with their job counts using the correct relationship name
    categories = JobCategory.objects.annotate(
        job_count=Count('job', filter=Q(job__status='publish'))
    )
    
    context = {
        'page_title': 'Career Opportunities',
        'jobs': jobs,
        'categories': categories
    }
    
    return render(request, 'home.html', context)


def job_listings(request):
    """
    View for displaying job listings with filtering and pagination
    """
    # Get all published jobs
    jobs_list = Job.objects.filter(status='publish')
    
    # Get filter parameters from request
    search_query = request.GET.get('search', '')
    location_filter = request.GET.get('location', '')
    category_filter = request.GET.get('category', '')
    sort_by = request.GET.get('sort', 'newest')
    
    # Apply filters
    if search_query:
        jobs_list = jobs_list.filter(
            Q(title__icontains=search_query) |
            Q(description__icontains=search_query)
        )
    
    if location_filter and location_filter != 'All Locations':
        jobs_list = jobs_list.filter(location__icontains=location_filter)
    
    if category_filter and category_filter != 'All Categories':
        jobs_list = jobs_list.filter(category__name__icontains=category_filter)
    
    # Apply sorting
    if sort_by == 'salary_high_low':
        jobs_list = jobs_list.order_by('-salary_start')
    elif sort_by == 'salary_low_high':
        jobs_list = jobs_list.order_by('salary_start')
    elif sort_by == 'relevant':
        # You might want to implement a more sophisticated relevance algorithm
        jobs_list = jobs_list.order_by('-created_at')
    else:  # newest first by default
        jobs_list = jobs_list.order_by('-created_at')
    
    # Get unique locations and categories for filters
    locations = Job.objects.filter(status='publish').values_list('location', flat=True).distinct()
    categories = JobCategory.objects.annotate(job_count=Count('job')).filter(job_count__gt=0)
    
    # Pagination
    paginator = Paginator(jobs_list, 10)  # Show 10 jobs per page
    page = request.GET.get('page')
    
    try:
        jobs = paginator.page(page)
    except PageNotAnInteger:
        jobs = paginator.page(1)
    except EmptyPage:
        jobs = paginator.page(paginator.num_pages)
    
    context = {
        'page_title': 'Career Opportunities',
        'jobs': jobs,
        'locations': locations,
        'categories': categories,
        'search_query': search_query,
        'selected_location': location_filter,
        'selected_category': category_filter,
        'selected_sort': sort_by,
        'total_jobs_count': jobs_list.count(),
    }
    
    return render(request, 'job_listings.html', context)


def job_detail_frontend(request, job_id):
    job = get_object_or_404(Job, id=job_id)
    
    # Check if user has applied
    has_applied = False
    application = None
    if request.user.is_authenticated:
        application = JobApplication.objects.filter(
            job=job, 
            applicant=request.user
        ).first()
        has_applied = application is not None
    
    # Get related jobs (same category or similar title)
    related_jobs = Job.objects.filter(
        Q(category=job.category) | Q(title__icontains=job.title.split()[0])
    ).exclude(id=job.id)[:4]
    
    # Calculate how long ago the job was posted
    time_since_posted = timezone.now() - job.created_at
    hours_ago = int(time_since_posted.total_seconds() / 3600)
    
    context = {
        'job': job,
        'related_jobs': related_jobs,
        'hours_ago': hours_ago,
        'has_applied': has_applied,
        'application': application,
    }
    
    return render(request, 'job_detail.html', context)


def jobs_by_category(request, category_slug):
    category = get_object_or_404(JobCategory, slug=category_slug)
    
    # Get filter parameters
    search_query = request.GET.get('search', '')
    selected_sort = request.GET.get('sort', 'newest')
    
    # Base queryset
    jobs = Job.objects.filter(category=category, status='publish')
    
    # Apply search filter
    if search_query:
        jobs = jobs.filter(
            Q(title__icontains=search_query) |
            Q(description__icontains=search_query) |
            Q(location__icontains=search_query)
        )
    
    # Apply sorting
    if selected_sort == 'salary_high':
        jobs = jobs.order_by('-salary_start')
    elif selected_sort == 'salary_low':
        jobs = jobs.order_by('salary_start')
    elif selected_sort == 'relevant':
        # You can customize relevance sorting based on your needs
        jobs = jobs.order_by('-created_at')
    else:  # newest (default)
        jobs = jobs.order_by('-created_at')
    
    # Pagination
    paginator = Paginator(jobs, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Additional context data
    total_jobs = jobs.count()
    active_jobs = jobs.filter(application_deadline__gte=timezone.now().date()).count()
    avg_salary = jobs.aggregate(avg_salary=Avg('salary_start'))['avg_salary'] or 0
    
    context = {
        'category': category,
        'jobs': page_obj,
        'search_query': search_query,
        'selected_sort': selected_sort,
        'total_jobs': total_jobs,
        'active_jobs': active_jobs,
        'avg_salary': int(avg_salary),
        'related_categories': JobCategory.objects.exclude(id=category.id).annotate(
            job_count=Count('job', filter=Q(job__status='publish'))
        )[:6],
    }
    
    return render(request, 'category_jobs.html', context)


def about(request):
    """
    View for the About page
    """
    context = {
        'page_title': 'About Our Company',
        'team_members': [
            {'name': 'John Doe', 'role': 'CEO', 'bio': 'Founder with 10+ years of experience...'},
            {'name': 'Jane Smith', 'role': 'CTO', 'bio': 'Technology expert specializing in...'},
            # Add more team members as needed
        ],
        'company_history': 'Our company was founded in 2010 with a mission to...',
    }
    return render(request, 'about-us.html', context)


def blog(request):
    context = {
        'page_title': 'Our Blog',
    }
    return render(request, 'blogs.html', context)


def contact_us(request):
    context = {
        'page_title': 'Contact Us',
    }
    return render(request, 'contact-us.html', context)