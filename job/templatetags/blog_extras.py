from django import template

register = template.Library()

@register.filter
def divide(value, arg):
    try:
        return int(value) / int(arg)
    except (ValueError, ZeroDivisionError):
        return 0

@register.filter
def wordcount(value):
    # Count words in HTML content by stripping tags
    import re
    text = re.sub(r'<[^>]+>', '', value)
    return len(text.split())