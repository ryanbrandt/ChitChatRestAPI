from django.db.models.signals import post_save, pre_delete
from django.db.models import Q
from django.dispatch import receiver
from .models import UserMessage, GroupMessage, UserGroup, Notification, ExtendedUser
from datetime import datetime


@receiver(signal=post_save, sender=UserMessage)
def generate_usermessage_notification(instance, created, **kwargs):
    '''
    Signals: triggered post_save of a UserMessage instance; generates a corresponding Notification instance for receiver
    :param instance: Newly instantiated UserMessage
    :param created: Creation status of new instance
    :return: null
    '''
    if created:
        # if no notification exists for this user regarding new UserMessages from author, create new
        if not Notification.objects.filter(user=instance.user, activity_type='UM', source_id=instance.message.author.id):
            Notification.objects.create(activity_type='UM', source_id=instance.message.author.id, user=instance.user, details=f'New messages from {instance.message.author.username}')
        else:
            Notification.objects.filter(user=instance.user, activity_type='UM', source_id=instance.message.author.id).update(timestamp=datetime.now(), read=0)


@receiver(signal=post_save, sender=GroupMessage)
def generate_groupmessage_notification(instance, created, **kwargs):
    '''
    Signals: triggered by post_save of a GroupMessage instance; generates corresponding Notification instance(s) for group members
    :param instance: Newly instantiated GroupMessage
    :param created: Creation status of new instance
    :return: null
    '''
    if created:
        # get all group members excluding message author, check if notification exists
        group_members = UserGroup.objects.filter(Q(group=instance.group) & ~Q(user=instance.message.author)).values_list('user', flat=True)
        for member in group_members:
            if not Notification.objects.filter(user=member, source_id=instance.group.id, activity_type='GM'):
                Notification.objects.create(activity_type='GM', source_id=instance.group.id, user=ExtendedUser.objects.get(id=member), details=f'New messages from {instance.group.name}')
            else:
                Notification.objects.filter(user=ExtendedUser.objects.get(id=member), activity_type='GM', source_id=instance.group.id).update(timestamp=datetime.now(), read=0)


@receiver(signal=post_save, sender=UserGroup)
def generate_usergroup_notification(instance, created, **kwargs):
    '''
    Signals: triggered by post_save of a UserGroup instance; generates corresponding Notification instance for UserGroup.user
    :param instance: Newly instantiated UserGroup
    :param created: Creation status of new instance
    :return: null
    '''
    if created:
        # if no notification exists for this user regarding membership to this group, create new
        if not Notification.objects.filter(user=instance.user, activity_type='AG', source_id=instance.group.id):
            Notification.objects.create(user=instance.user, activity_type='AG', source_id=instance.group.id, details=f'You have been added to {instance.group.name}')
        else:
            Notification.objects.filter(user=instance.user, activity_type='AG', source_id=instance.group.id).update(timestamp=datetime.now(), read=0)