from django.contrib import admin
from .models import Section, UserSectionPermission
from django.contrib import admin
import os
from django.conf import settings
from django.http import HttpResponse




@admin.register(Section)
class SectionAdmin(admin.ModelAdmin):
    list_display = ('name','path')



@admin.register(UserSectionPermission)
class UserSectionPermissionAdmin(admin.ModelAdmin):
    list_display = ('user', 'section', 'permission')
    list_filter = ('permission', 'section')
    search_fields = ('user__username',)

