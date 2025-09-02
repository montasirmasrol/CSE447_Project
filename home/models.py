# from django.db import models
# from django.contrib.auth.models import User

# class Contact(models.Model):
#     name = models.CharField(max_length=122)
#     email = models.CharField(max_length=122)
#     phone = models.CharField(max_length=11)
#     desc = models.TextField()
#     date = models.DateField()

#     def __str__(self):
#         return self.name


# class UserProfile(models.Model):
#     user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
#     encrypted_profile_picture = models.BinaryField(null=True, blank=True)

#     def __str__(self):
#         return self.user.username


# class EncryptedPost(models.Model):
#     user = models.ForeignKey(User, on_delete=models.CASCADE)
#     encrypted_title = models.TextField()
#     encrypted_content = models.TextField()
#     created_at = models.DateTimeField(auto_now_add=True)  # Changed from 'date'

#     def __str__(self):
#         return f"Post by {self.user.username} at {self.created_at}"




# from django.db import models
# from django.contrib.auth.models import User

# class Contact(models.Model):
#     name = models.CharField(max_length=122)
#     email = models.CharField(max_length=122)
#     phone = models.CharField(max_length=11)
#     desc = models.TextField()
#     date = models.DateField()

#     def __str__(self):
#         return self.name


# class UserProfile(models.Model):
#     user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
#     encrypted_profile_picture = models.BinaryField(null=True, blank=True)

#     def __str__(self):
#         return self.user.username


# class EncryptedPost(models.Model):
#     user = models.ForeignKey(User, on_delete=models.CASCADE)
#     encrypted_title = models.TextField()
#     encrypted_content = models.TextField()
#     created_at = models.DateTimeField(auto_now_add=True)
    
#     # MAC fields to ensure integrity
#     title_mac = models.CharField(max_length=128, blank=True, null=True)
#     content_mac = models.CharField(max_length=128, blank=True, null=True)

#     def __str__(self):
#         return f"Post by {self.user.username} at {self.created_at}"






from django.db import models
from django.contrib.auth.models import User


class Contact(models.Model):
    name = models.CharField(max_length=122)
    email = models.CharField(max_length=122)
    phone = models.CharField(max_length=11)
    desc = models.TextField()
    date = models.DateField()

    def __str__(self):
        return self.name


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    encrypted_profile_picture = models.BinaryField(null=True, blank=True)

    # MAC fields for integrity verification of user details
    email_mac = models.CharField(max_length=128, blank=True, null=True)
    first_name_mac = models.CharField(max_length=128, blank=True, null=True)
    last_name_mac = models.CharField(max_length=128, blank=True, null=True)

    def __str__(self):
        return self.user.username


class EncryptedPost(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    encrypted_title = models.TextField()
    encrypted_content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    # MAC fields to ensure integrity
    title_mac = models.CharField(max_length=128, blank=True, null=True)
    content_mac = models.CharField(max_length=128, blank=True, null=True)

    def __str__(self):
        return f"Post by {self.user.username} at {self.created_at}"
