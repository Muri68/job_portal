from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.core.validators import RegexValidator, FileExtensionValidator
from django.conf import settings
from django.utils import timezone


class UserManager(BaseUserManager):
    """Custom manager for User model with email as the unique identifier."""

    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("role", User.Role.JOB_SEEKER)
        return self._create_user(email, password, **extra_fields)
    
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("role", User.Role.SITE_ADMIN)
        return self._create_user(email, password, **extra_fields)
    
    def create_admin_user(self, email, password=None, first_name="", last_name="", **extra_fields):
        """Create a site admin user with proper permissions"""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", False)  # Regular admin, not superuser
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("role", User.Role.SITE_ADMIN)
        
        if not email:
            raise ValueError("The Email field must be set")
        
        user = self._create_user(email, password, **extra_fields)
        user.first_name = first_name
        user.last_name = last_name
        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    """Custom User model with role-based accounts."""

    class Role(models.TextChoices):
        JOB_SEEKER = "job_seeker", "Job Seeker"
        SITE_ADMIN = "site_admin", "Site Admin"
        EMPLOYER = "employer", "Employer"
        RECRUITER = "recruiter", "Recruiter"

    email = models.EmailField(unique=True, db_index=True)
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    role = models.CharField(max_length=30, choices=Role.choices, default=Role.JOB_SEEKER)

    # Permissions
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)

    # Timestamps
    date_joined = models.DateTimeField(default=timezone.now)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []
    
    def get_full_name(self):
        """Return the full name of the user"""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        elif self.first_name:
            return self.first_name
        elif self.last_name:
            return self.last_name
        else:
            return self.email.split('@')[0]
    
    def is_job_seeker(self):
        return self.role == self.Role.JOB_SEEKER
    
    def is_employer(self):
        return self.role == self.Role.EMPLOYER
    
    def is_site_admin(self):
        return self.role == self.Role.SITE_ADMIN or self.is_superuser

    def __str__(self):
        return f"{self.email} ({self.role})"
    
    def get_display_name(self):
        """Return the best available display name"""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        elif self.first_name:
            return self.first_name
        elif self.last_name:
            return self.last_name
        else:
            return self.email
    
    def get_initials(self):
        """Return initials for avatars"""
        if self.first_name and self.last_name:
            return f"{self.first_name[0]}{self.last_name[0]}".upper()
        elif self.first_name:
            return self.first_name[0].upper()
        elif self.last_name:
            return self.last_name[0].upper()
        else:
            return self.email[0].upper()
    
    @classmethod
    def get_active_superusers_count(cls):
        """Return count of active superusers"""
        return cls.objects.filter(is_superuser=True, is_active=True).count()
    
    def can_be_deleted(self, request_user):
        """
        Check if this user can be deleted
        - Cannot delete yourself
        - Cannot delete last active superuser
        """
        if self == request_user:
            return False, "You cannot delete your own account."
        
        if self.is_superuser and self.is_active:
            active_superusers_count = User.objects.filter(
                is_superuser=True, 
                is_active=True
            ).exclude(id=self.id).count()
            
            if active_superusers_count == 0:
                return False, "Cannot delete the last active superuser."
        
        return True, ""




PHONE_REGEX = RegexValidator(
    regex=r'^\+?1?\d{9,15}$',
    message="Phone number must be in the format: +999999999 (up to 15 digits)."
)

def upload_to_resume(instance, filename):
    """Dynamic path for storing resumes by user and timestamp."""
    timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
    return f"resumes/user_{instance.user.id}/{timestamp}_{filename}"


class JobSeekerProfile(models.Model):
    """Profile extension for job seekers."""

    CONTACT_CHOICES = [
        ('email', 'Email'),
        ('phone', 'Phone'),
        ('both', 'Both'),
    ]

    EXPERIENCE_CHOICES = [
        ('entry', 'Entry Level (0-2 years)'),
        ('mid', 'Mid Level (3-5 years)'),
        ('senior', 'Senior Level (6-9 years)'),
        ('executive', 'Executive (10+ years)'),
    ]

    EDUCATION_CHOICES = [
        ('highschool', 'High School'),
        ('associate', 'Associate Degree'),
        ('bachelor', "Bachelor's Degree"),
        ('master', "Master's Degree"),
        ('phd', 'PhD'),
    ]

    # Link to user
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="jobseeker_profile"
    )

    # Basic info
    phone = models.CharField(max_length=20, blank=True)
    address = models.TextField(blank=True)
    linkedin_url = models.URLField(blank=True)
    portfolio_url = models.URLField(blank=True)

    # Application materials
    resume = models.FileField(
        upload_to=upload_to_resume,
        validators=[FileExtensionValidator(['pdf',])],
        blank=True, null=True
    )
    cover_letter = models.TextField(blank=True, null=True)

    # Preferences
    preferred_contact_method = models.CharField(
        max_length=20,
        choices=CONTACT_CHOICES,
        default='email'
    )

    # Career info
    years_of_experience = models.CharField(max_length=20, choices=EXPERIENCE_CHOICES)
    highest_education = models.CharField(max_length=20, choices=EDUCATION_CHOICES)
    key_skills = models.TextField(
        help_text="Enter skills separated by commas, e.g., Python, Django, SQL",
        blank=True, null=True
    )
    location = models.CharField(max_length=100)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def get_skills_list(self):
        """Convert key_skills string into list."""
        return [skill.strip() for skill in self.key_skills.split(",") if skill.strip()] if self.key_skills else []
    
    @property
    def display_name(self):
        """Get display name with fallback"""
        full_name = self.user.get_full_name()
        return full_name if full_name else self.user.email

    def get_experience_display_short(self):
        """Get shortened experience display"""
        experience_map = {
            'entry': '0-2 years',
            'mid': '3-5 years', 
            'senior': '6-9 years',
            'executive': '10+ years'
        }
        return experience_map.get(self.years_of_experience, self.years_of_experience)

    def has_complete_profile(self):
        """Check if profile is sufficiently complete"""
        required_fields = [self.user.first_name, self.user.last_name, self.location, self.years_of_experience]
        return all(required_fields) and len(self.get_skills_list()) >= 3



    def __str__(self):
        return f"JobSeekerProfile({self.user.email})"
