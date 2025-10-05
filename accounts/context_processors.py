

def user_roles(request):
    if request.user.is_authenticated:
        return {
            'is_job_seeker': request.user.is_job_seeker(),
            'is_employer': request.user.is_employer(),
            'is_site_admin': request.user.is_site_admin(),
        }
    return {}