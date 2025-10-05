# In your_app/templatetags/custom_filters.py
from django import template

register = template.Library()

@register.filter
def get_range(value, end):
    try:
        value = int(value)
        end = int(end)
        if value <= end:
            return range(value, end + 1)
        else:
            return range(value, value)
    except (ValueError, TypeError):
        return range(1, 2)