from django.contrib import admin
from .models import *


admin.site.register(JobCategory)
admin.site.register(Job)
admin.site.register(JobApplication)
admin.site.register(SavedJob)


from django.contrib import admin
from .models import AboutUs, OurValue, TeamMember, CompanyStat

class OurValueInline(admin.TabularInline):
    model = OurValue
    extra = 1
    fields = ['icon', 'title', 'description', 'order', 'is_active']
    ordering = ['order']

class TeamMemberInline(admin.TabularInline):
    model = TeamMember
    extra = 1
    fields = ['name', 'position', 'image', 'order', 'is_active']
    ordering = ['order']

class CompanyStatInline(admin.TabularInline):
    model = CompanyStat
    extra = 1
    fields = ['icon', 'number', 'label', 'order']
    ordering = ['order']

@admin.register(AboutUs)
class AboutUsAdmin(admin.ModelAdmin):
    list_display = ['title', 'is_active', 'created_at', 'updated_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['title', 'description', 'mission', 'vision']
    fieldsets = (
        ('Basic Information', {
            'fields': ('title', 'description', 'image', 'is_active')
        }),
        ('Mission & Vision', {
            'fields': ('mission', 'vision')
        }),
    )

    def has_add_permission(self, request):
        # Only allow one AboutUs instance
        if self.model.objects.count() >= 1:
            return False
        return super().has_add_permission(request)

@admin.register(OurValue)
class OurValueAdmin(admin.ModelAdmin):
    list_display = ['title', 'icon', 'order', 'is_active']
    list_filter = ['is_active',]
    search_fields = ['title', 'description']
    list_editable = ['order', 'is_active']
    ordering = ['order',]

@admin.register(TeamMember)
class TeamMemberAdmin(admin.ModelAdmin):
    list_display = ['name', 'position', 'order', 'is_active']
    list_filter = ['is_active',]
    search_fields = ['name', 'position', 'bio']
    list_editable = ['order', 'is_active']
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'position', 'image', 'bio', 'order', 'is_active')
        }),
        ('Social Media', {
            'fields': ('linkedin_url', 'twitter_url', 'github_url', 'portfolio_url'),
            'classes': ('collapse',)
        }),
    )
    ordering = ['order',]

@admin.register(CompanyStat)
class CompanyStatAdmin(admin.ModelAdmin):
    list_display = ['label', 'number', 'icon', 'order']
    search_fields = ['label', 'number']
    list_editable = ['order']
    ordering = ['order',]