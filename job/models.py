
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






from django.db import models
from django.contrib.auth.models import User
from django.core.validators import FileExtensionValidator
from django.utils import timezone
from django.conf import settings

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
    
    # Notification tracking fields
    status_changed_at = models.DateTimeField(null=True, blank=True)
    last_status_change = models.CharField(max_length=100, blank=True, verbose_name="Last Status Change")
    status_change_notification_sent = models.BooleanField(default=False)
    status_change_read = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-applied_at']
        unique_together = ['job', 'applicant_email']
        verbose_name = "Job Application"
        verbose_name_plural = "Job Applications"
        indexes = [
            models.Index(fields=['status', 'applied_at']),
            models.Index(fields=['applicant_email']),
            models.Index(fields=['job', 'status']),
            models.Index(fields=['status_changed_at']),  # New index for notifications
            models.Index(fields=['status_change_read']),  # New index for notifications
        ]
    
    def __str__(self):
        return f"{self.applicant_name} - {self.job.title}"
    
    def save(self, *args, **kwargs):
        """
        Override save method to track status changes for notifications
        """
        # Check if this is an update and status has changed
        if self.pk:
            try:
                old_instance = JobApplication.objects.get(pk=self.pk)
                if old_instance.status != self.status:
                    # Record the status change for notifications
                    self.status_changed_at = timezone.now()
                    self.last_status_change = f"{old_instance.get_status_display()} → {self.get_status_display()}"
                    self.status_change_notification_sent = False
                    self.status_change_read = False
                    
                    # Also update last_contact_date when status changes
                    self.last_contact_date = timezone.now()
            except JobApplication.DoesNotExist:
                # This is a new instance, not an update
                pass
        
        super().save(*args, **kwargs)
    
    @property
    def is_recent(self):
        """Check if application was submitted within last 7 days"""
        return (timezone.now() - self.applied_at).days <= 7
    
    @property
    def application_age(self):
        """Return age of application in days"""
        return (timezone.now() - self.applied_at).days
    
    @property
    def has_unread_status_change(self):
        """Check if there's an unread status change notification"""
        return self.status_changed_at and not self.status_change_read
    
    @property
    def status_change_age(self):
        """Return how long ago the status was changed in days"""
        if self.status_changed_at:
            delta = timezone.now() - self.status_changed_at
            return delta.days
        return None
    
    @property
    def status_change_age_humanized(self):
        """Return human-readable time since status change"""
        if self.status_changed_at:
            delta = timezone.now() - self.status_changed_at
            
            if delta.days == 0:
                if delta.seconds < 3600:  # Less than 1 hour
                    minutes = delta.seconds // 60
                    return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
                else:  # Less than 24 hours
                    hours = delta.seconds // 3600
                    return f"{hours} hour{'s' if hours != 1 else ''} ago"
            elif delta.days == 1:
                return "yesterday"
            elif delta.days < 7:
                return f"{delta.days} days ago"
            elif delta.days < 30:
                weeks = delta.days // 7
                return f"{weeks} week{'s' if weeks != 1 else ''} ago"
            else:
                months = delta.days // 30
                return f"{months} month{'s' if months != 1 else ''} ago"
        return "Never"
    
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
    
    def mark_notification_read(self):
        """Mark status change notification as read"""
        self.status_change_read = True
        self.save(update_fields=['status_change_read'])
    
    def mark_notification_unread(self):
        """Mark status change notification as unread"""
        self.status_change_read = False
        self.save(update_fields=['status_change_read'])
    
    def get_notification_context(self):
        """Get context data for notification display"""
        return {
            'application': self,
            'job_title': self.job.title,
            'company_name': self.job.company_name,
            'old_status': self.last_status_change.split(' → ')[0] if ' → ' in self.last_status_change else None,
            'new_status': self.get_status_display(),
            'changed_at': self.status_changed_at,
            'is_unread': not self.status_change_read,
        }
    
    
    
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



class AboutUs(models.Model):
    """Main About Us content"""
    title = models.CharField(max_length=200, default="About Our Company")
    description = CKEditor5Field('Text', config_name='extends')
    image = models.ImageField(
        upload_to='about/us/',
        help_text="Main about us image (recommended: 800x600px)",
        blank=True,
        null=True
    )
    mission = CKEditor5Field('Text', config_name='extends')
    vision = CKEditor5Field('Text', config_name='extends')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "About Us"
        verbose_name_plural = "About Us"

    def __str__(self):
        return "About Us Content"

class OurValue(models.Model):
    """Company values with icons"""
    ICON_CHOICES = [
        ('bi-people', 'Teamwork'),
        ('bi-lightbulb', 'Innovation'),
        ('bi-shield-check', 'Integrity'),
        ('bi-heart', 'Passion'),
        ('bi-award', 'Excellence'),
        ('bi-graph-up', 'Growth'),
        ('bi-hand-thumbs-up', 'Quality'),
        ('bi-clock', 'Commitment'),
        ('bi-globe', 'Global'),
        ('bi-cup', 'Success'),
    ]

    icon = models.CharField(max_length=50, choices=ICON_CHOICES, help_text="Select an icon for this value")
    title = models.CharField(max_length=100)
    description = models.TextField()  # Keep as TextField for simplicity
    order = models.PositiveIntegerField(default=0, help_text="Order in which values are displayed")
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = "Our Value"
        verbose_name_plural = "Our Values"
        ordering = ['order', 'title']

    def __str__(self):
        return self.title

class TeamMember(models.Model):
    """Team member information"""
    name = models.CharField(max_length=100)
    position = models.CharField(max_length=100)
    image = models.ImageField(
        upload_to='about/team/',
        help_text="Team member photo (recommended: 400x400px)",
        blank=True,
        null=True
    )
    bio = models.TextField(help_text="Short bio/description")  # Keep as TextField
    order = models.PositiveIntegerField(default=0, help_text="Order in which team members are displayed")
    is_active = models.BooleanField(default=True)

    # Social media handles
    linkedin_url = models.URLField(blank=True, verbose_name="LinkedIn Profile")
    twitter_url = models.URLField(blank=True, verbose_name="Twitter Profile")
    github_url = models.URLField(blank=True, verbose_name="GitHub Profile")
    portfolio_url = models.URLField(blank=True, verbose_name="Portfolio Website")

    class Meta:
        verbose_name = "Team Member"
        verbose_name_plural = "Team Members"
        ordering = ['order', 'name']

    def __str__(self):
        return f"{self.name} - {self.position}"

class CompanyStat(models.Model):
    """Company statistics/achievements"""
    icon = models.CharField(max_length=50, choices=OurValue.ICON_CHOICES)
    number = models.CharField(max_length=50, help_text="e.g., 100+, 5000, 99%")
    label = models.CharField(max_length=100, help_text="e.g., Projects Completed, Happy Clients")
    order = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = "Company Stat"
        verbose_name_plural = "Company Stats"
        ordering = ['order']

    def __str__(self):
        return f"{self.number} {self.label}"
    
    

class ContactInfo(models.Model):
    """Company contact information"""
    COMPANY_INFO_CHOICES = [
        ('address', 'Address'),
        ('phone', 'Phone'),
        ('email', 'Email'),
        ('hours', 'Business Hours'),
    ]

    contact_type = models.CharField(max_length=20, choices=COMPANY_INFO_CHOICES)
    title = models.CharField(max_length=100, help_text="e.g., Main Office, Support Line")
    value = models.TextField(help_text="Contact information")
    icon = models.CharField(max_length=50, default='bi-geo-alt', help_text="Bootstrap icon class")
    order = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = "Contact Information"
        verbose_name_plural = "Contact Information"
        ordering = ['order', 'contact_type']

    def __str__(self):
        return f"{self.get_contact_type_display()} - {self.title}"

class FAQ(models.Model):
    """Frequently Asked Questions"""
    question = models.CharField(max_length=255)
    answer = models.TextField()
    order = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "FAQ"
        verbose_name_plural = "FAQs"
        ordering = ['order', 'question']

    def __str__(self):
        return self.question

class ContactMessage(models.Model):
    """Messages received from contact form"""
    STATUS_CHOICES = [
        ('new', 'New'),
        ('read', 'Read'),
        ('replied', 'Replied'),
        ('closed', 'Closed'),
    ]

    name = models.CharField(max_length=100)
    email = models.EmailField()
    subject = models.CharField(max_length=200)
    message = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Contact Message"
        verbose_name_plural = "Contact Messages"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} - {self.subject}"

class SiteSetting(models.Model):
    """General site settings for contact page"""
    site_name = models.CharField(max_length=100, default="Tech Recruitment UK")
    contact_email = models.EmailField(default="info@techrecruitment.com")
    support_email = models.EmailField(default="support@techrecruitment.com")
    phone_number = models.CharField(max_length=20, default="+1 (123) 456-7890")
    address = models.TextField(default="1234 Street Name, City, State, Country 12345")
    business_hours = models.TextField(default="Monday - Friday: 9:00 AM - 6:00 PM")
    map_embed_code = models.TextField(blank=True, help_text="Google Maps embed code")
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = "Site Setting"
        verbose_name_plural = "Site Settings"

    def __str__(self):
        return "Site Settings"

    def save(self, *args, **kwargs):
        # Ensure only one instance exists
        if not self.pk and SiteSetting.objects.exists():
            # Update existing instance instead of creating new one
            existing = SiteSetting.objects.first()
            existing.site_name = self.site_name
            existing.contact_email = self.contact_email
            existing.support_email = self.support_email
            existing.phone_number = self.phone_number
            existing.address = self.address
            existing.business_hours = self.business_hours
            existing.map_embed_code = self.map_embed_code
            existing.is_active = self.is_active
            return existing.save(*args, **kwargs)
        return super().save(*args, **kwargs)