
from django.db import models
# from django.contrib.auth.models import User
from django.utils import timezone
from django_ckeditor_5.fields import CKEditor5Field
from django.db.models import Count
from django.conf import settings
from django.core.validators import FileExtensionValidator

class JobCategory(models.Model):
    name = models.CharField(max_length=100)
    slug = models.SlugField(unique=True)
    description = models.TextField(blank=True)
    
    class Meta:
        verbose_name_plural = 'Categories'
        ordering = ['name']
        
    def __str__(self):
        return self.name
    
    def job_count(self):
        return self.job_set.filter(status='publish').count()
    
    
    
class Job(models.Model):
    JOB_TYPE_CHOICES = [
        ('full_time', 'Full Time'),
        ('part_time', 'Part Time'),
        ('contract', 'Contract'),
        ('internship', 'Internship'),
        ('remote', 'Remote'),
    ]
    
    WORKPLACE_TYPE_CHOICES = [
        ('onsite', 'On Site'),
        ('remote', 'Remote'),
        ('hybrid', 'Hybrid'),
    ]
    
    JOB_STATUS_CHOICES = [
        ('publish', 'Publish'),
        ('draft', 'Draft'),
        ('inactive', 'Inactive'),        
    ]
    
    # Basic job info
    title = models.CharField(max_length=200)
    category = models.ForeignKey(JobCategory, on_delete=models.CASCADE)
    short_description = models.TextField(max_length=500, blank=True)
    description = CKEditor5Field('Text', config_name='extends')
    
    # Job details
    location = models.CharField(max_length=200)
    job_type = models.CharField(max_length=50, choices=JOB_TYPE_CHOICES)
    workplace_type = models.CharField(max_length=50, choices=WORKPLACE_TYPE_CHOICES)
    
    # Salary and status
    salary_start = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    status = models.CharField(max_length=50, choices=JOB_STATUS_CHOICES, default='publish')
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    application_deadline = models.DateField()
    
    class Meta:
        ordering = ['-created_at']
    
    def is_expired(self):
        return self.application_deadline < timezone.now().date()
    
    def __str__(self):
        return f"{self.title} - {self.title}"
    
    @property
    def is_new_job(self):
        """Return True if job was never updated (created_at equals updated_at)"""
        return self.updated_at.replace(microsecond=0) == self.created_at.replace(microsecond=0)
    
    def get_applications_count(self):
        """Get the number of applications for this job"""
        return self.applications.count()
    
    def get_applications(self):
        """Get all applications for this job"""
        return self.applications.all()
    
    def has_applications(self):
        """Check if job has any applications"""
        return self.applications.exists()
    
    
    
class SavedJob(models.Model):
    """
    Model for job seekers to save/bookmark jobs they're interested in.
    """
    job_seeker = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="saved_jobs",
        # limit_choices_to={'role': settings.AUTH_USER_MODEL.USER.Role.JOB_SEEKER}
    )
    
    job = models.ForeignKey(
        Job,
        on_delete=models.CASCADE,
        related_name="saved_by_users"
    )
    
    # Metadata
    saved_at = models.DateTimeField(auto_now_add=True)
    notes = models.TextField(
        blank=True,
        null=True,
        help_text="Personal notes about this job opportunity"
    )
    
    # Categorization
    CATEGORY_CHOICES = [
        ('interested', 'Interested'),
        ('applying_soon', 'Applying Soon'),
        ('research', 'Need to Research'),
        ('comparison', 'For Comparison'),
        ('favorite', 'Favorite'),
    ]
    
    category = models.CharField(
        max_length=20,
        choices=CATEGORY_CHOICES,
        default='interested'
    )
    
    # Reminder feature
    reminder_date = models.DateTimeField(
        blank=True,
        null=True,
        help_text="Set a reminder for this job"
    )
    
    class Meta:
        unique_together = ['job_seeker', 'job']  # Prevent duplicate saves
        ordering = ['-saved_at']
        verbose_name = "Saved Job"
        verbose_name_plural = "Saved Jobs"
    
    def __str__(self):
        return f"{self.job_seeker.email} saved {self.job.title}"
    
    @property
    def is_reminder_due(self):
        """Check if reminder is due"""
        if self.reminder_date:
            return timezone.now() >= self.reminder_date
        return False
    
    @property
    def days_since_saved(self):
        """Return number of days since job was saved"""
        return (timezone.now() - self.saved_at).days







class JobApplication(models.Model):
    STATUS_CHOICES = [
        ('pending', '📝 Pending'),
        ('reviewed', '👀 Reviewed'),
        ('shortlisted', '⭐ Shortlisted'),
        ('interview', '💼 Interview'),
        ('rejected', '❌ Rejected'),
        ('accepted', '✅ Accepted'),
    ]
    
    SOURCE_CHOICES = [
        ('website', 'Website'),
        ('linkedin', 'LinkedIn'),
        ('indeed', 'Indeed'),
        ('referral', 'Employee Referral'),
        ('other', 'Other'),
    ]
    
    job = models.ForeignKey(Job, on_delete=models.CASCADE, related_name='applications')
    applicant = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True, related_name='job_applications')
    
    # Applicant information
    applicant_name = models.CharField(max_length=200)
    applicant_email = models.EmailField()
    applicant_phone = models.CharField(max_length=20, blank=True)
    
    # Professional information
    current_company = models.CharField(max_length=200, blank=True, verbose_name="Current Company")
    current_position = models.CharField(max_length=200, blank=True, verbose_name="Current Position")
    years_of_experience = models.PositiveIntegerField(null=True, blank=True, verbose_name="Years of Experience")
    
    # Professional profile links
    linkedin_profile = models.URLField(blank=True, verbose_name="LinkedIn Profile")
    github_profile = models.URLField(blank=True, verbose_name="GitHub Profile")
    portfolio_url = models.URLField(blank=True, verbose_name="Portfolio URL")
    
    # Application documents
    resume = models.FileField(
        upload_to='resumes/%Y/%m/%d/',
        validators=[FileExtensionValidator(allowed_extensions=['pdf',])],
        help_text="Upload your resume (PDF)"
    )
    cover_letter = models.TextField(
        help_text="Why are you interested in this position?",
        verbose_name="Cover Letter"
    )
    
    # Application metadata
    applied_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='pending')
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    
    # Communication tracking
    last_contact_date = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True, help_text="Internal notes about this application")
    
    class Meta:
        ordering = ['-applied_at']
        unique_together = ['job', 'applicant_email']
        verbose_name = "Job Application"
        verbose_name_plural = "Job Applications"
        indexes = [
            models.Index(fields=['status', 'applied_at']),
            models.Index(fields=['applicant_email']),
            models.Index(fields=['job', 'status']),
        ]
    
    def __str__(self):
        return f"{self.applicant_name} - {self.job.title}"
    
    @property
    def is_recent(self):
        """Check if application was submitted within last 7 days"""
        from django.utils import timezone
        return (timezone.now() - self.applied_at).days <= 7
    
    @property
    def application_age(self):
        """Return age of application in days"""
        from django.utils import timezone
        return (timezone.now() - self.applied_at).days
    
    def get_status_badge_class(self):
        """Return Bootstrap badge class for status"""
        status_classes = {
            'pending': 'bg-secondary',
            'reviewed': 'bg-info',
            'shortlisted': 'bg-warning',
            'interview': 'bg-primary',
            'rejected': 'bg-danger',
            'accepted': 'bg-success',
        }
        return status_classes.get(self.status, 'bg-secondary')
    
    
    
from django.db import models
from django.conf import settings
from django.utils import timezone

class Interview(models.Model):
    INTERVIEW_TYPE_CHOICES = [
        ('online', 'Online'),
        ('onsite', 'On Site'),
    ]

    application = models.ForeignKey('JobApplication', on_delete=models.CASCADE, related_name='interviews')
    description = models.TextField()
    date_time = models.DateTimeField()
    interview_type = models.CharField(max_length=20, choices=INTERVIEW_TYPE_CHOICES)
    location = models.CharField(max_length=255, blank=True, help_text="Required if interview is On Site")
    meeting_link = models.URLField(blank=True, help_text="Required if interview is Online")

    # Assign interview to a staff member (Recruiter / HR / Manager)
    assigned_to = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="assigned_interviews")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-date_time']
        verbose_name = "Interview"
        verbose_name_plural = "Interviews"

    def __str__(self):
        return f"Interview for {self.application.applicant_name} on {self.date_time.strftime('%Y-%m-%d %H:%M')}"

    @property
    def is_upcoming(self):
        return self.date_time >= timezone.now()

    def clean(self):
        """
        Adding validation to ensure location is required for onsite,
        and meeting link is required for online.
        """
        from django.core.exceptions import ValidationError

        if self.interview_type == 'onsite' and not self.location:
            raise ValidationError("Location is required for On Site interviews.")
        if self.interview_type == 'online' and not self.meeting_link:
            raise ValidationError("Meeting Link is required for Online interviews.")
