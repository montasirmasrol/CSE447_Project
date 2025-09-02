from django.contrib import admin
from home.models import Contact, UserProfile, EncryptedPost

admin.site.register(Contact)
admin.site.register(UserProfile)
admin.site.register(EncryptedPost)
