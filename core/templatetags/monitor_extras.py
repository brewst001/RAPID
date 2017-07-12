from django import template
import hashlib

register = template.Library()

@register.filter
def digest(value):

    unique = hashlib.md5(value.encode('utf-8')).hexdigest()
    return unique


@register.filter
def filtertags(monitor,user):

    result = monitor.filter(owner=user)
    return result
