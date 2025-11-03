from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import Count, Q, Avg
from django.utils import timezone

from job.models import Job, JobCategory, JobApplication
from job.forms import JobForm, SaveJobForm
from accounts.models import User
from job.views_pkg.admin_views import get_client_ip
from blog.models import BlogPost, Category


# ---------------------------------------------------------------------------------------------------------------------
######################################## FRONTEND VIEWS
# ---------------------------------------------------------------------------------------------------------------------

def index(request):
    jobs = Job.objects.filter(status='publish')[:4]
    
    # Get all categories with their job counts using the correct relationship name
    categories = JobCategory.objects.annotate(
        job_count=Count('job', filter=Q(job__status='publish'))
    )
    
    # Get the first category and its jobs
    first_category = categories.first()
    if first_category:
        category_jobs = Job.objects.filter(
            category=first_category, 
            status='publish'
        )[:8]  # Limit to 8 jobs
    else:
        category_jobs = []
    
    context = {
        'jobs': Job.objects.filter(status='publish')[:6],
        'blogs': BlogPost.objects.filter(status='published')[:3],
        'page_title': 'Career Opportunities',
        # 'jobs': jobs,
        'categories': categories,
        'first_category': first_category,
        'category_jobs': category_jobs,
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


from django.views.decorators.csrf import ensure_csrf_cookie
from job.models import SavedJob  # Make sure to import SavedJob


@ensure_csrf_cookie
def job_detail_frontend(request, job_id):
    job = get_object_or_404(Job, id=job_id)
    
    # Check if user has applied
    has_applied = False
    application = None
    is_saved = False
    
    if request.user.is_authenticated:
        # Check application
        application = JobApplication.objects.filter(
            job=job, 
            applicant=request.user
        ).first()
        has_applied = application is not None
        
        # Check if job is saved/bookmarked
        is_saved = SavedJob.objects.filter(
            job_seeker=request.user,
            job=job
        ).exists()
    
    # Get related jobs (same category or similar title)
    related_jobs = Job.objects.filter(
        Q(category=job.category) | Q(title__icontains=job.title.split()[0])
    ).exclude(id=job.id)[:4]
    
    # Calculate how long ago the job was posted
    time_since_posted = timezone.now() - job.created_at
    hours_ago = int(time_since_posted.total_seconds() / 3600)
    
    # Create share text for social media
    share_text = f"Check out this job: {job.title}"
    
    context = {
        'job': job,
        'related_jobs': related_jobs,
        'hours_ago': hours_ago,
        'has_applied': has_applied,
        'application': application,
        'is_saved': is_saved,
        'share_text': share_text,
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


from django.shortcuts import render, get_object_or_404
from .models import AboutUs, OurValue, TeamMember, CompanyStat

def about(request):
    """
    View for the About page
    """
    # Get the active AboutUs instance or create a default one
    about_us = AboutUs.objects.filter(is_active=True).first()
    
    if not about_us:
        about_us = AboutUs.objects.create(
            title="About Our Company",
            description="We are a passionate team dedicated to delivering exceptional solutions...",
            mission="Our mission is to provide outstanding services and build lasting relationships with our clients.",
            vision="To be the leading company in our industry, recognized for innovation and excellence.",
            is_active=True
        )
    
    # Get all active items
    our_values = OurValue.objects.filter(is_active=True).order_by('order')
    team_members = TeamMember.objects.filter(is_active=True).order_by('order')
    company_stats = CompanyStat.objects.filter(is_active=True).order_by('order')

    context = {
        'page_title': about_us.title,
        'about_us': about_us,
        'our_values': our_values,
        'team_members': team_members,
        'company_stats': company_stats,
    }
    return render(request, 'about-us.html', context)




def blog(request):
    # Get all published blogs ordered by publish date (newest first)
    blog_list = BlogPost.objects.filter(status='published').order_by('-published_date')
    
    # Pagination - 6 posts per page
    paginator = Paginator(blog_list, 6)
    page = request.GET.get('page')
    
    try:
        blogs = paginator.page(page)
    except PageNotAnInteger:
        # If page is not an integer, deliver first page
        blogs = paginator.page(1)
    except EmptyPage:
        # If page is out of range, deliver last page of results
        blogs = paginator.page(paginator.num_pages)
    
    # Get categories with their blog post counts
    categories = Category.objects.annotate(
        blog_count=Count('blog_posts', filter=Q(blog_posts__status='published'))
    )
    
    # Get recent posts for sidebar (exclude current page posts)
    recent_posts = BlogPost.objects.filter(status='published').order_by('-published_date')[:5]
    
    context = {
        'page_title': 'Our Blog',
        'blogs': blogs,
        'categories': categories,
        'recent_posts': recent_posts,
    }
    return render(request, 'blogs.html', context)



def blog_detail(request, slug):
    # Get the blog post or return 404
    blog = get_object_or_404(
        BlogPost.objects.select_related('author', 'category')
                       .prefetch_related('tags'),
        slug=slug, 
        status='published'
    )
    
    # Increment view count
    blog.view_count += 1
    blog.save(update_fields=['view_count'])
    
    # Get related posts (same category, excluding current post)
    related_posts = BlogPost.objects.filter(
        category=blog.category,
        status='published'
    ).exclude(id=blog.id).order_by('-published_date')[:3]
    
    # Get categories with counts for sidebar
    categories = Category.objects.annotate(
        blog_count=Count('blog_posts', filter=Q(blog_posts__status='published'))
    )
    
    # Get recent posts for sidebar
    recent_posts = BlogPost.objects.filter(status='published').order_by('-published_date')[:5]
    
    # Get next and previous posts
    next_post = BlogPost.objects.filter(
        status='published',
        published_date__gt=blog.published_date
    ).order_by('published_date').first()
    
    previous_post = BlogPost.objects.filter(
        status='published',
        published_date__lt=blog.published_date
    ).order_by('-published_date').first()
    
    context = {
        'blog': blog,
        'related_posts': related_posts,
        'categories': categories,
        'recent_posts': recent_posts,
        'next_post': next_post,
        'previous_post': previous_post,
        'page_title': blog.title,
        'meta_description': blog.meta_description or blog.excerpt,
    }
    
    return render(request, 'blog/blog_detail.html', context)
def blog_detail(request, slug):
    # Get the blog post or return 404
    blog = get_object_or_404(
        BlogPost.objects.select_related('author', 'category')
                       .prefetch_related('tags'),
        slug=slug, 
        status='published'
    )
    
    # Increment view count
    blog.view_count += 1
    blog.save(update_fields=['view_count'])
    
    # Calculate reading time (approx 200 words per minute)
    import re
    content_text = re.sub(r'<[^>]+>', '', blog.content)
    word_count = len(content_text.split())
    reading_time = max(1, word_count // 200)  # At least 1 minute
    
    # Get related posts (same category, excluding current post)
    related_posts = BlogPost.objects.filter(
        category=blog.category,
        status='published'
    ).exclude(id=blog.id).order_by('-published_date')[:3]
    
    # Get categories with counts for sidebar
    categories = Category.objects.annotate(
        blog_count=Count('blog_posts', filter=Q(blog_posts__status='published'))
    )
    
    # Get recent posts for sidebar
    recent_posts = BlogPost.objects.filter(status='published').order_by('-published_date')[:5]
    
    # Get next and previous posts
    next_post = BlogPost.objects.filter(
        status='published',
        published_date__gt=blog.published_date
    ).order_by('published_date').first()
    
    previous_post = BlogPost.objects.filter(
        status='published',
        published_date__lt=blog.published_date
    ).order_by('-published_date').first()
    
    context = {
        'blog': blog,
        'related_posts': related_posts,
        'categories': categories,
        'recent_posts': recent_posts,
        'next_post': next_post,
        'previous_post': previous_post,
        'reading_time': reading_time,
        'page_title': blog.title,
        'meta_description': blog.meta_description or blog.excerpt,
    }
    
    return render(request, 'blog_detail.html', context)



from job.models import ContactMessage, ContactInfo, FAQ, SiteSetting
from job.forms import ContactMessageForm, ContactInfoForm, FAQForm, SiteSettingForm

def contact_us(request):
    """Public contact page"""
    site_settings = SiteSetting.objects.filter(is_active=True).first()
    if not site_settings:
        site_settings = SiteSetting.objects.create()
    
    contact_info = ContactInfo.objects.filter(is_active=True).order_by('order')
    faqs = FAQ.objects.filter(is_active=True).order_by('order')
    
    if request.method == 'POST':
        form = ContactMessageForm(request.POST)
        if form.is_valid():
            contact_message = form.save(commit=False)
            
            # Capture additional data
            contact_message.ip_address = get_client_ip(request)
            contact_message.user_agent = request.META.get('HTTP_USER_AGENT', '')
            contact_message.save()
            
            messages.success(request, 'Thank you for your message! We will get back to you soon.')
            return render(request, 'contact-us.html', {
                'form': ContactMessageForm(),
                'site_settings': site_settings,
                'contact_info': contact_info,
                'faqs': faqs,
                'message_sent': True
            })
    else:
        form = ContactMessageForm()
    
    context = {
        'page_title': 'Contact Us',
        'form': form,
        'site_settings': site_settings,
        'contact_info': contact_info,
        'faqs': faqs,
        'message_sent': False
    }
    return render(request, 'contact-us.html', context)