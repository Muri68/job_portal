from django.urls import path, include
from . import views
from .views_pkg import jobseeker_views, admin_views


# Admin URL patterns
admin_urls = [
    # Dashboard
    path('dashboard/', admin_views.admin_dashboard, name='admin-dashboard'),
    
    # Job management URLs
    path('jobs/', admin_views.job_list, name='job_list'),
    path('jobs/manage/', admin_views.job_manage, name='job_manage'),
    path('jobs/<int:job_id>/', admin_views.job_detail, name='job_detail'),
    path('jobs/manage/<int:job_id>/', admin_views.job_manage, name='job_manage_edit'),
    path('jobs/delete/<int:job_id>/', admin_views.job_delete, name='job_delete'),
    
    # Applicant management URLs
    path('applicants/', admin_views.applicants_list, name='applicants_list'),
    path('applicants/<int:pk>/', admin_views.applicant_detail, name='applicant_detail'),
    path('applications/<int:application_id>/compose-email/', admin_views.compose_email, name='compose_email'),
    
    # Application management URLs
    path('jobs/<int:job_id>/applications/', admin_views.job_applications, name='admin-job_applications'),
    path('applications/update-status/<int:application_id>/', admin_views.update_application_status, name='update_application_status'),
    
    # Admin user management URLs
    path('admin-users/add/', admin_views.add_admin_user, name='add_admin_user'),
    path('admin-users/', admin_views.admin_users_list, name='admin_users_list'),
    path('admin-users/<int:user_id>/toggle/', admin_views.toggle_admin_status, name='toggle_admin_status'),
    path('admin-users/<int:user_id>/delete/', admin_views.delete_admin_user, name='delete_admin_user'),
    
    # Profile & Settings URLs
    path('settings/', admin_views.admin_settings, name='admin_settings'),
    path('settings/profile/', admin_views.user_profile, name='user_profile'),
    path('settings/password/', admin_views.admin_change_password, name='change_password'),
    
    # Management
    path('dashboard/about/manage/', admin_views.AboutUsManageView.as_view(), name='about_manage'),
    
    # Values
    path('dashboard/about/values/', admin_views.OurValueListView.as_view(), name='our_values_list'),
    path('dashboard/about/values/add/', admin_views.OurValueCreateView.as_view(), name='our_value_add'),
    path('dashboard/about/values/<int:pk>/edit/', admin_views.OurValueUpdateView.as_view(), name='our_value_edit'),
    path('dashboard/about/values/<int:pk>/delete/', admin_views.OurValueDeleteView.as_view(), name='our_value_delete'),
    
    # Team Members
    path('dashboard/about/team/', admin_views.TeamMemberListView.as_view(), name='team_members_list'),
    path('dashboard/about/team/add/', admin_views.TeamMemberCreateView.as_view(), name='team_member_add'),
    path('dashboard/about/team/<int:pk>/edit/', admin_views.TeamMemberUpdateView.as_view(), name='team_member_edit'),
    path('dashboard/about/team/<int:pk>/delete/', admin_views.TeamMemberDeleteView.as_view(), name='team_member_delete'),
    
    # Company Stats
    path('dashboard/about/stats/', admin_views.CompanyStatListView.as_view(), name='company_stats_list'),
    path('dashboard/about/stats/add/', admin_views.CompanyStatCreateView.as_view(), name='company_stat_add'),
    path('dashboard/about/stats/<int:pk>/edit/', admin_views.CompanyStatUpdateView.as_view(), name='company_stat_edit'),
    path('dashboard/about/stats/<int:pk>/delete/', admin_views.CompanyStatDeleteView.as_view(), name='company_stat_delete'),
    
    path('dashboard/about/faqs/', admin_views.FAQListView.as_view(), name='faq_list'),
    path('dashboard/about/faqs/add/', admin_views.FAQCreateView.as_view(), name='faq_add'),
    path('dashboard/about/faqs/<int:pk>/edit/', admin_views.FAQUpdateView.as_view(), name='faq_edit'),
    path('dashboard/about/faqs/<int:pk>/delete/', admin_views.FAQDeleteView.as_view(), name='faq_delete'),
    
    
    # Management
    path('dashboard/contact/messages/', admin_views.ContactMessageListView.as_view(), name='contact_messages_list'),
    path('dashboard/contact/messages/<int:pk>/', admin_views.ContactMessageDetailView.as_view(), name='contact_message_detail'),
    path('dashboard/contact/messages/<int:pk>/delete/', admin_views.ContactMessageDeleteView.as_view(), name='contact_message_delete'),
    
    path('dashboard/contact/info/', admin_views.ContactInfoListView.as_view(), name='contact_info_list'),
    path('dashboard/contact/info/add/', admin_views.ContactInfoCreateView.as_view(), name='contact_info_add'),
    path('dashboard/contact/info/<int:pk>/edit/', admin_views.ContactInfoUpdateView.as_view(), name='contact_info_edit'),
    path('dashboard/contact/info/<int:pk>/delete/', admin_views.ContactInfoDeleteView.as_view(), name='contact_info_delete'),
    
    path('dashboard/contact/settings/', admin_views.SiteSettingUpdateView.as_view(), name='contact_settings'),
]


# Main URL patterns
urlpatterns = [
    # Admin URLs
    path('administrator/', include(admin_urls)),

    # Frontend URLs
    path('', views.index, name='index'),
    path('about/', views.about, name='about'),
    path('blog/', views.blog, name='blog'),
    path('contact/', views.contact_us, name='contact_us'),
    path('job-listings/', views.job_listings, name='job_listings'),
    path('job/<int:job_id>/detail/', views.job_detail_frontend, name='job_detail_frontend'),
    path('category/<slug:category_slug>/', views.jobs_by_category, name='jobs_by_category'),

    # Job Application URLs
    path('job/<int:job_id>/apply/', jobseeker_views.apply_for_job, name='apply_for_job'),
    path('application/<int:application_id>/confirmation/', jobseeker_views.application_confirmation, name='application_confirmation'),
    path('my-applications/', jobseeker_views.my_applications, name='my_applications'),
    path('application/<int:application_id>/', jobseeker_views.application_detail, name='application_detail'),
    path('job/<int:job_id>/check-status/', jobseeker_views.check_application_status, name='check_application_status'),
    path('job/<int:job_id>/quick-apply/', jobseeker_views.quick_apply, name='quick_apply'),
    
    path('dashboard/notification/', jobseeker_views.job_seeker_notification, name='job_seeker_notification'),
    path('notifications/mark-all-read/', jobseeker_views.mark_all_notifications_read, name='mark_all_notifications_read'),
    path('notifications/<int:application_id>/mark-read/', jobseeker_views.mark_single_notification_read, name='mark_single_notification_read'),
    path('notifications/unread-count/', jobseeker_views.get_unread_notification_count, name='get_unread_notification_count'),
    
    # Job Seeker Dashboard & Profile URLs
    path('dashboard/', jobseeker_views.jobseeker_dashboard, name='jobseeker_dashboard'),
    path('change-password/', jobseeker_views.jobseeker_change_password, name='jobseeker-change_password'),
    path('profile/', jobseeker_views.profile_view, name='profile_view'),
    path('profile/edit/', jobseeker_views.profile_edit, name='profile_edit'),
    path('profile/upload-resume/', jobseeker_views.upload_resume, name='upload_resume'),
    path('profile/public/<int:pk>/', jobseeker_views.PublicProfileView.as_view(), name='public_profile'),
    
    # Job Bookmark URLs
    path('job/<int:job_id>/save/', jobseeker_views.save_job, name='save_job'),
    path('job/<int:job_id>/unsave/', jobseeker_views.unsave_job, name='unsave_job'),
    path('job/<int:job_id>/toggle-save/', jobseeker_views.toggle_save_job, name='toggle_save_job'),
    path('bookmarked-Job/', jobseeker_views.saved_jobs_list, name='saved_jobs'),
    path('bookmarked-Job/<int:saved_job_id>/update/', jobseeker_views.update_saved_job, name='update_saved_job'),
    path('job/<int:job_id>/check-saved/', jobseeker_views.check_job_saved, name='check_job_saved'),
]