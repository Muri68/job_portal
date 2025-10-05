from django import forms
from django.contrib.auth import authenticate
from django.contrib.auth.forms import ReadOnlyPasswordHashField, UserCreationForm, PasswordChangeForm
from django.core.validators import RegexValidator, FileExtensionValidator
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model

from .models import JobSeekerProfile

User = get_user_model()


class EmailAuthenticationForm(forms.Form):
    email = forms.EmailField(
        label="Email Address",
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your email address', 
            'autocomplete': 'email'
        })
    )
    password = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your password',
            'autocomplete': 'current-password'
        })
    )
    remember_me = forms.BooleanField(
        required=False,
        label="Remember me",
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )

    def get_user(self):
        """Try to authenticate and return user if credentials are valid"""
        if not hasattr(self, 'cleaned_data') or not self.cleaned_data:
            return None
            
        email = self.cleaned_data.get('email')
        password = self.cleaned_data.get('password')
        
        if email and password:
            return authenticate(
                request=None,  # Don't pass request to avoid session issues
                username=email,
                password=password,
                backend='accounts.backends.EmailBackend'
            )
        return None


class TOTPForm(forms.Form):
    token = forms.IntegerField(
        widget=forms.NumberInput(attrs={
            "class": "form-control", 
            "placeholder": "123456"
        })
    )
    trust_device = forms.BooleanField(required=False)


class JobSeekerSignupForm(forms.ModelForm):
    password1 = forms.CharField(label="Password", widget=forms.PasswordInput)
    password2 = forms.CharField(label="Confirm Password", widget=forms.PasswordInput)

    # JobSeekerProfile fields
    phone = forms.CharField(required=True, max_length=20)
    address = forms.CharField(widget=forms.Textarea, required=False)
    linkedin_url = forms.URLField(required=False)
    portfolio_url = forms.URLField(required=False)
    years_of_experience = forms.ChoiceField(
        choices=JobSeekerProfile.EXPERIENCE_CHOICES, 
        required=True
    )
    highest_education = forms.ChoiceField(
        choices=JobSeekerProfile.EDUCATION_CHOICES, 
        required=True
    )
    key_skills = forms.CharField(
        help_text="Comma-separated skills", 
        required=False,
        widget=forms.TextInput(attrs={'placeholder': 'e.g. JavaScript, Project Management, UX Design'})
    )
    location = forms.CharField(required=True, max_length=100)
    
    # Add the resume field that's in your template
    resume = forms.FileField(
        required=False,
        validators=[FileExtensionValidator(['pdf',])],
        help_text="Accepted format: PDF. Max file size: 5MB"
    )
    
    # Add preferred_contact_method that's in your template
    preferred_contact_method = forms.ChoiceField(
        choices=JobSeekerProfile.CONTACT_CHOICES,
        required=False,
        initial='email'
    )

    class Meta:
        model = User
        fields = ["first_name", "last_name", "email"]

    def clean_password2(self):
        pwd1 = self.cleaned_data.get("password1")
        pwd2 = self.cleaned_data.get("password2")
        if pwd1 and pwd2 and pwd1 != pwd2:
            raise forms.ValidationError("Passwords don't match")
        return pwd2

    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        if phone and len(phone) < 10:
            raise forms.ValidationError("Please enter a valid phone number")
        return phone

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        user.role = User.Role.JOB_SEEKER
        user.is_active = False
        
        if commit:
            user.save()
            
            # Handle file upload separately
            resume_file = self.cleaned_data.get('resume')
            
            # Create the JobSeekerProfile with ALL fields
            job_seeker_profile = JobSeekerProfile(
                user=user,
                phone=self.cleaned_data.get("phone"),
                address=self.cleaned_data.get("address"),
                linkedin_url=self.cleaned_data.get("linkedin_url"),
                portfolio_url=self.cleaned_data.get("portfolio_url"),
                years_of_experience=self.cleaned_data.get("years_of_experience"),
                highest_education=self.cleaned_data.get("highest_education"),
                key_skills=self.cleaned_data.get("key_skills"),
                location=self.cleaned_data.get("location"),
                preferred_contact_method=self.cleaned_data.get("preferred_contact_method", 'email'),
            )
            
            # Handle file upload if present
            if resume_file:
                job_seeker_profile.resume = resume_file
                
            job_seeker_profile.save()
            
        return user


class AdminUserCreationForm(UserCreationForm):
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter email address'
        })
    )
    first_name = forms.CharField(
        required=True,
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter first name'
        })
    )
    last_name = forms.CharField(
        required=True,
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter last name'
        })
    )
    password1 = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter password'
        })
    )
    password2 = forms.CharField(
        label="Confirm Password",
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm password'
        })
    )
    send_welcome_email = forms.BooleanField(
        required=False,
        initial=True,
        label="Send welcome email with login credentials"
    )

    class Meta:
        model = User
        fields = ('email', 'first_name', 'last_name', 'password1', 'password2')

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise ValidationError("A user with this email already exists.")
        return email

    def save(self, commit=True):
        user = super().save(commit=False)
        user.role = User.Role.SITE_ADMIN
        user.is_staff = True
        user.is_active = True
        
        if commit:
            user.save()
        return user


class UserProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email']
        widgets = {
            'first_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter your first name'
            }),
            'last_name': forms.TextInput(attrs={
                'class': 'form-control', 
                'placeholder': 'Enter your last name'
            }),
            'email': forms.EmailInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter your email address'
            }),
        }
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exclude(id=self.instance.id).exists():
            raise ValidationError("A user with this email already exists.")
        return email


class CustomPasswordChangeForm(PasswordChangeForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['old_password'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Enter current password',
            'id': 'id_old_password'
        })
        self.fields['new_password1'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Enter new password',
            'id': 'id_new_password1'
        })
        self.fields['new_password2'].widget.attrs.update({
            'class': 'form-control', 
            'placeholder': 'Confirm new password',
            'id': 'id_new_password2'
        })