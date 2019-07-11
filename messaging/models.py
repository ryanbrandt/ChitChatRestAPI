from django.db import models
from django.contrib.auth import settings
from django.utils import timezone
from django.contrib.auth.models import AbstractUser


''' Extended User Model, extends Django's OOB User model with additional attributes as needed '''
class ExtendedUser(AbstractUser):
    phone = models.BigIntegerField(unique=True)
    ''' User phone number, mandatory for password retrieval; distinct '''
    is_public = models.BooleanField(default=True)
    ''' Denotes if User is publc (e.g. searchable) '''


''' Defines a messaging group '''
class MessagingGroup(models.Model):
    name = models.CharField(max_length=50, unique=True)
    ''' Group display name, mandatory '''


''' Describes relationship between Users and MessagingGroups '''
class UserGroup(models.Model):
    user = models.ForeignKey(ExtendedUser, on_delete=models.CASCADE)
    group = models.ForeignKey(MessagingGroup, on_delete=models.CASCADE, related_name='in_group')

    class Meta:
        # obviously no redundancies here
        unique_together = (('user', 'group'))


''' Base message model, fields cascade to an instance of UserMessage or GroupMessage '''
class Message(models.Model):
    author = models.ForeignKey(ExtendedUser, on_delete=models.CASCADE)
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    ''' Timestamp of message creation, defaults to now '''


''' Defines a User-to-User instance of Message '''
class UserMessage(models.Model):
    user = models.ForeignKey(ExtendedUser, on_delete=models.CASCADE)
    ''' ExtendedUser in reception '''
    message = models.ForeignKey(Message, on_delete=models.CASCADE)


''' Defines a User-to-Group instance of Message '''
class GroupMessage(models.Model):
    group = models.ForeignKey(MessagingGroup, on_delete=models.CASCADE)
    ''' UserGroup in reception '''
    message = models.ForeignKey(Message, on_delete=models.CASCADE)


''' General 'Activity Stream' Notification model '''
class Notification(models.Model):
    # currently supported notification activities
    activity_choices = (
        ('UM','UserMessage'),
        ('GM', 'GroupMessage'),
        ('AG', 'UserGroup')
    )
    user = models.ForeignKey(ExtendedUser, on_delete=models.CASCADE)
    activity_type = models.CharField(max_length=2, choices=activity_choices)
    source_id = models.IntegerField()
    ''' activity type will allow us to reference an appropriate source via source_id '''
    timestamp = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False)
    details = models.CharField(max_length=40)
