from django.contrib import admin
from django.utils.html import format_html
from .models import Category, Tag, BlogPost, BlogComment, BlogImage

class BlogImageInline(admin.TabularInline):
    model = BlogImage
    extra = 1

class BlogCommentInline(admin.TabularInline):
    model = BlogComment
    extra = 0
    readonly_fields = ['author', 'content', 'created_at']
    can_delete = False
    
    def has_add_permission(self, request, obj=None):
        return False

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ['get_name_display', 'slug', 'created_at']
    list_filter = ['created_at']
    search_fields = ['name']
    prepopulated_fields = {'slug': ['name']}

@admin.register(Tag)
class TagAdmin(admin.ModelAdmin):
    list_display = ['name', 'slug']
    search_fields = ['name']
    prepopulated_fields = {'slug': ['name']}

@admin.register(BlogPost)
class BlogPostAdmin(admin.ModelAdmin):
    list_display = ['title', 'slug', 'category', 'author', 'status', 'published_date', 'featured', 'view_count']
    list_filter = ['status', 'category', 'featured', 'published_date', 'created_at']
    search_fields = ['title', 'excerpt', 'content']
    readonly_fields = ['slug', 'view_count', 'created_at', 'updated_at']
    date_hierarchy = 'published_date'
    inlines = [BlogImageInline, BlogCommentInline]
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('title', 'slug', 'excerpt', 'content')
        }),
        ('Metadata', {
            'fields': ('author', 'category', 'tags', 'featured_image')
        }),
        ('Status & Dates', {
            'fields': ('status', 'published_date')
        }),
        ('SEO', {
            'fields': ('meta_description', 'meta_keywords'),
            'classes': ('collapse',)
        }),
        ('Statistics', {
            'fields': ('view_count', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def save_model(self, request, obj, form, change):
        if not obj.author_id:
            obj.author = request.user
        super().save_model(request, obj, form, change)

@admin.register(BlogComment)
class BlogCommentAdmin(admin.ModelAdmin):
    list_display = ['author', 'post', 'created_at', 'approved']
    list_filter = ['approved', 'created_at']
    search_fields = ['author__username', 'post__title', 'content']
    actions = ['approve_comments', 'disapprove_comments']
    
    def approve_comments(self, request, queryset):
        queryset.update(approved=True)
    approve_comments.short_description = "Approve selected comments"
    
    def disapprove_comments(self, request, queryset):
        queryset.update(approved=False)
    disapprove_comments.short_description = "Disapprove selected comments"

@admin.register(BlogImage)
class BlogImageAdmin(admin.ModelAdmin):
    list_display = ['post', 'image_preview', 'caption', 'created_at']
    list_filter = ['created_at']
    search_fields = ['post__title', 'caption']
    
    def image_preview(self, obj):
        if obj.image:
            return format_html('<img src="{}" width="50" height="50" style="object-fit: cover;" />', obj.image.url)
        return "-"
    image_preview.short_description = "Preview"