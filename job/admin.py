from django.contrib import admin
from .models import *


admin.site.register(JobCategory)
admin.site.register(Job)
admin.site.register(JobApplication)
admin.site.register(SavedJob)