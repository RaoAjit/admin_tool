from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta

class PasswordResetOTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_reset_otps')
    otp_code = models.CharField(max_length=6)  # e.g., 6-digit code
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    def save(self, *args, **kwargs):
        # Set expiration if not already set
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=15)  # OTP valid for 15 min
        super().save(*args, **kwargs)

    def is_valid(self):
        return not self.is_used and timezone.now() < self.expires_at

    def __str__(self):
        return f"OTP for {self.user.username} - {self.otp_code}"



from django.db import models
from django.contrib.auth.models import User

class Section(models.Model):
    """
    Represents a root section like auth, logs, company_data, etc.
    """
    name = models.CharField(max_length=100, unique=True)
    path=models.CharField(max_length=1000)
    def __str__(self):
        return self.name


class UserSectionPermission(models.Model):
    """
    Mapping: User → Section → Permission
    """
    PERMISSION_CHOICES = (
        ('view', 'View Only'),
        ('edit', 'View + Edit'),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    section = models.ForeignKey(Section, on_delete=models.CASCADE)
    permission = models.CharField(max_length=10, choices=PERMISSION_CHOICES)
    
    class Meta:
        unique_together = ('user', 'section')

    def __str__(self):
        return f"{self.user.username} → {self.section.name} ({self.permission})"
