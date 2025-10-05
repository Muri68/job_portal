import threading
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings

class EmailThread(threading.Thread):
    def __init__(self, subject, template_name, context, to_email):
        self.subject = subject
        self.template_name = template_name
        self.context = context
        self.to_email = to_email
        threading.Thread.__init__(self)

    def run(self):
        try:
            # Render HTML content
            html_content = render_to_string(self.template_name, self.context)
            text_content = strip_tags(html_content)

            # Create email
            email = EmailMultiAlternatives(
                self.subject,
                text_content,
                settings.DEFAULT_FROM_EMAIL,
                [self.to_email]
            )
            email.attach_alternative(html_content, "text/html")
            email.send(fail_silently=False)
            
            print(f"Email sent successfully to {self.to_email}")
        except Exception as e:
            print(f"Error sending email to {self.to_email}: {str(e)}")
            # You can log this error to a file or monitoring service

def send_async_email(subject, template_name, context, to_email):
    """Send email asynchronously using threading"""
    EmailThread(subject, template_name, context, to_email).start()