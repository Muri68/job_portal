from django import forms
from .models import Job, JobApplication, Interview, SavedJob
from django.utils import timezone
import os


class JobForm(forms.ModelForm):
    class Meta:
        model = Job
        fields = [
            'title', 'category', 'description', 'location', 
            'job_type', 'workplace_type', 'salary_start', 
            'status', 'application_deadline'
        ]
        widgets = {
            'application_deadline': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'salary_start': forms.NumberInput(attrs={'step': '0.01', 'min': '0', 'class': 'form-control'}),
            'title': forms.TextInput(attrs={'class': 'form-control'}),
            'location': forms.TextInput(attrs={'class': 'form-control'}),
            'category': forms.Select(attrs={'class': 'form-select'}),
            'job_type': forms.Select(attrs={'class': 'form-select'}),
            'workplace_type': forms.Select(attrs={'class': 'form-select'}),
            'status': forms.Select(attrs={'class': 'form-select'}),
        }

    

class ApplicationStatusForm(forms.ModelForm):
    class Meta:
        model = JobApplication
        fields = ['status']
        widgets = {
            'status': forms.Select(attrs={'class': 'form-select'})
        }


class InterviewForm(forms.ModelForm):
    class Meta:
        model = Interview
        fields = ["description", "date_time", "interview_type", "location", "meeting_link", "assigned_to"]
        widgets = {
            "description": forms.Textarea(attrs={"class": "form-control", "rows": 3}),
            "date_time": forms.DateTimeInput(attrs={"type": "datetime-local", "class": "form-control"}),
            "interview_type": forms.Select(attrs={"class": "form-select"}),
            "location": forms.TextInput(attrs={"class": "form-control"}),
            "meeting_link": forms.URLInput(attrs={"class": "form-control"}),
            "assigned_to": forms.Select(attrs={"class": "form-select"}),
        }





from django import forms
from django.core.exceptions import ValidationError
from .models import JobApplication

class JobApplicationForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        self.job = kwargs.pop('job', None)
        super().__init__(*args, **kwargs)

    def clean_applicant_email(self):
        email = self.cleaned_data.get('applicant_email')
        job = self.job  # use job from form init

        if job and email:
            existing_application = JobApplication.objects.filter(
                job=job,
                applicant_email=email
            ).exists()
            if existing_application:
                raise ValidationError("You have already applied to this job position.")
        return email
    
    agree_to_terms = forms.BooleanField(
        required=True,
        error_messages={'required': 'You must agree to the terms and conditions'},
        label='I agree to the processing of my personal data'
    )
    
    resume = forms.FileField(
        widget=forms.FileInput(attrs={
            'accept': '.pdf,.doc,.docx',
            'class': 'form-control'
        })
    )
    
    class Meta:
        model = JobApplication
        fields = [
            'applicant_name', 'applicant_email', 'applicant_phone',
            'current_company', 'current_position', 'years_of_experience',
            'linkedin_profile', 'github_profile', 'portfolio_url',
            'resume', 'cover_letter'
        ]
        widgets = {
            'applicant_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Your full name'}),
            'applicant_email': forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'your.email@example.com'}),
            'applicant_phone': forms.TextInput(attrs={'class': 'form-control', 'placeholder': '+1 (555) 123-4567'}),
            'current_company': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Your current company'}),
            'current_position': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Your current position'}),
            'years_of_experience': forms.NumberInput(attrs={'class': 'form-control', 'min': '0', 'max': '50'}),
            'linkedin_profile': forms.URLInput(attrs={'class': 'form-control', 'placeholder': 'https://linkedin.com/in/yourprofile'}),
            'github_profile': forms.URLInput(attrs={'class': 'form-control', 'placeholder': 'https://github.com/yourusername'}),
            'portfolio_url': forms.URLInput(attrs={'class': 'form-control', 'placeholder': 'https://yourportfolio.com'}),
            'cover_letter': forms.Textarea(attrs={
                'class': 'form-control', 
                'rows': 6,
                'placeholder': 'Tell us why you are interested in this position and why you would be a great fit...'
            }),
            'source': forms.Select(attrs={'class': 'form-control'}),
        }
        help_texts = {
            'resume': 'Supported formats: PDF, DOC, DOCX (Max: 5MB)',
            'cover_letter': 'Customize your cover letter for this specific position',
        }
    
    def clean_resume(self):
        resume = self.cleaned_data.get('resume')
        if resume:
            # Check file size (5MB limit)
            if resume.size > 5 * 1024 * 1024:
                raise ValidationError("File size must be under 5MB")
            
            # Check file extension
            valid_extensions = ['.pdf',]
            extension = os.path.splitext(resume.name)[1].lower()
            if extension not in valid_extensions:
                raise ValidationError("Unsupported file format. Please upload PDF")
        
        return resume
    
    
    

class SaveJobForm(forms.ModelForm):
    class Meta:
        model = SavedJob
        fields = ['category', 'notes', 'reminder_date']
        widgets = {
            'category': forms.Select(attrs={
                'class': 'form-select',
                'id': 'saveJobCategory'
            }),
            'notes': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Add personal notes about this job...',
                'id': 'saveJobNotes'
            }),
            'reminder_date': forms.DateTimeInput(attrs={
                'class': 'form-control',
                'type': 'datetime-local',
                'id': 'saveJobReminder'
            }),
        }
        labels = {
            'category': 'Category',
            'notes': 'Personal Notes',
            'reminder_date': 'Set Reminder',
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['reminder_date'].required = False
        # Set minimum date for reminder (today)
        self.fields['reminder_date'].widget.attrs['min'] = timezone.now().strftime('%Y-%m-%dT%H:%M')
        
        
        



from django import forms
from django.core.exceptions import ValidationError
from accounts.models import JobSeekerProfile, User

class JobSeekerProfileForm(forms.ModelForm):
    # Add fields from User model with Bootstrap styling
    first_name = forms.CharField(
        max_length=150, 
        required=True, 
        widget=forms.TextInput(attrs={
            "class": "form-control", 
            "placeholder": "Enter your first name",
            "id": "first_name"
        })
    )
    
    last_name = forms.CharField(
        max_length=150, 
        required=True, 
        widget=forms.TextInput(attrs={
            "class": "form-control", 
            "placeholder": "Enter your last name",
            "id": "last_name"
        })
    )
    
    email = forms.EmailField(
        max_length=150, 
        required=True, 
        widget=forms.EmailInput(attrs={
            "class": "form-control", 
            "placeholder": "your.email@example.com",
            "id": "email"
        })
    )

    class Meta:
        model = JobSeekerProfile
        fields = [
            'first_name', 'last_name', 'email', 'phone', 'address', 
            'linkedin_url', 'portfolio_url', 'resume', 'cover_letter',
            'preferred_contact_method', 'years_of_experience', 
            'highest_education', 'key_skills', 'location'
        ]
        
        widgets = {
            'phone': forms.TextInput(attrs={
                'class': 'form-control', 
                'placeholder': '+1234567890',
                'id': 'phone'
            }),
            'address': forms.Textarea(attrs={
                'class': 'form-control', 
                'rows': 3,
                'placeholder': 'Enter your complete address...',
                'id': 'address'
            }),
            'linkedin_url': forms.URLInput(attrs={
                'class': 'form-control', 
                'placeholder': 'https://linkedin.com/in/yourprofile',
                'id': 'linkedin_url'
            }),
            'portfolio_url': forms.URLInput(attrs={
                'class': 'form-control', 
                'placeholder': 'https://yourportfolio.com',
                'id': 'portfolio_url'
            }),
            'resume': forms.FileInput(attrs={
                'class': 'form-control',
                'accept': '.pdf,.doc,.docx',
                'id': 'resume'
            }),
            'cover_letter': forms.Textarea(attrs={
                'class': 'form-control', 
                'rows': 5,
                'placeholder': 'Describe your professional background, skills, and career objectives...',
                'id': 'cover_letter'
            }),
            'preferred_contact_method': forms.Select(attrs={
                'class': 'form-select',
                'id': 'preferred_contact_method'
            }),
            'years_of_experience': forms.Select(attrs={
                'class': 'form-select',
                'id': 'years_of_experience'
            }),
            'highest_education': forms.Select(attrs={
                'class': 'form-select',
                'id': 'highest_education'
            }),
            'key_skills': forms.TextInput(attrs={
                'class': 'form-control', 
                'placeholder': 'Python, Django, SQL, JavaScript, React, etc.',
                'id': 'key_skills'
            }),
            'location': forms.TextInput(attrs={
                'class': 'form-control', 
                'placeholder': 'City, State, Country',
                'id': 'location'
            }),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Populate initial data from User model
        if self.instance and self.instance.user:
            self.fields['email'].initial = self.instance.user.email
            self.fields['first_name'].initial = self.instance.user.first_name
            self.fields['last_name'].initial = self.instance.user.last_name
        
        # Add Bootstrap classes to all fields that might not have them
        for field_name, field in self.fields.items():
            if 'class' not in field.widget.attrs:
                if isinstance(field.widget, forms.Select):
                    field.widget.attrs['class'] = 'form-select'
                elif isinstance(field.widget, forms.FileInput):
                    field.widget.attrs['class'] = 'form-control'
                else:
                    field.widget.attrs['class'] = 'form-control'
            
            # Add ID if not present
            if 'id' not in field.widget.attrs:
                field.widget.attrs['id'] = f'id_{field_name}'
    
    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        if phone:
            # Basic phone validation
            if not phone.replace('+', '').replace(' ', '').replace('-', '').isdigit():
                raise ValidationError("Please enter a valid phone number.")
        return phone
    
    def clean_linkedin_url(self):
        linkedin_url = self.cleaned_data.get('linkedin_url')
        if linkedin_url and 'linkedin.com' not in linkedin_url:
            raise ValidationError("Please enter a valid LinkedIn URL.")
        return linkedin_url
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email:
            # Check if email is already taken by another user
            if User.objects.filter(email=email).exclude(pk=self.instance.user.pk).exists():
                raise ValidationError("This email address is already in use.")
        return email
    
    def save(self, commit=True):
        profile = super().save(commit=False)
        # Update related User model
        if commit:
            profile.user.email = self.cleaned_data['email']
            profile.user.first_name = self.cleaned_data['first_name']
            profile.user.last_name = self.cleaned_data['last_name']
            profile.user.save()
            profile.save()
        return profile

class ResumeUploadForm(forms.ModelForm):
    class Meta:
        model = JobSeekerProfile
        fields = ['resume']
        widgets = {
            'resume': forms.FileInput(attrs={'accept': '.pdf'})
        }
        



from django import forms
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

class ChangePasswordForm(forms.Form):
    current_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'id': 'currentPassword',
            'placeholder': 'Enter your current password'
        }),
        label="Current Password"
    )
    
    new_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'id': 'newPassword',
            'placeholder': 'Enter your new password'
        }),
        label="New Password",
        validators=[validate_password]
    )
    
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'id': 'confirmPassword',
            'placeholder': 'Confirm your new password'
        }),
        label="Confirm New Password"
    )
    
    def __init__(self, user=None, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)
    
    def clean_current_password(self):
        current_password = self.cleaned_data.get('current_password')
        if not self.user.check_password(current_password):
            raise forms.ValidationError("Your current password is incorrect.")
        return current_password
    
    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get('new_password')
        confirm_password = cleaned_data.get('confirm_password')
        
        if new_password and confirm_password and new_password != confirm_password:
            raise forms.ValidationError("New password and confirmation do not match.")
        
        return cleaned_data
    
    
    
    
from django import forms
from django_ckeditor_5.widgets import CKEditor5Widget

class EmailForm(forms.Form):
    subject = forms.CharField(
        widget=forms.TextInput(attrs={
            "class": "form-control form-control-lg border-0 bg-light rounded-3",
            "placeholder": "Enter email subject..."
        })
    )
    message = forms.CharField(
        widget=CKEditor5Widget(config_name="default")
    )
    attach_resume = forms.BooleanField(required=False)
