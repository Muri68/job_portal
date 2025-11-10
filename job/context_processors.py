from .models import SiteSetting
        
        
def contact_info(request):
    """Add site settings to all templates"""
    try:
        settings = SiteSetting.objects.filter(is_active=True).first()
        if not settings:
            # Create default settings if none exist
            settings = SiteSetting.objects.create()
        return {
            'site_settings': settings
        }
    except Exception as e:
        # Log error and return None
        print(f"Error loading site settings: {e}")
        return {
            'site_settings': None
        }