

def user_roles(request):
    if request.user.is_authenticated:
        return {
            'is_job_seeker': request.user.is_job_seeker(),
            'is_employer': request.user.is_employer(),
            'is_site_admin': request.user.is_site_admin(),
        }
    return {}



from job.models import JobApplication

def notification_count(request):
    """
    Context processor to make unread notification count available in all templates
    """
    if request.user.is_authenticated and hasattr(request.user, 'job_applications'):
        unread_count = JobApplication.objects.filter(
            applicant=request.user,
            status_change_read=False,
            status_changed_at__isnull=False
        ).count()
        return {'unread_notification_count': unread_count}
    return {'unread_notification_count': 0}