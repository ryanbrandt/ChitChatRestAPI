from celery.schedules import crontab
from celery.task import periodic_task
from django.utils import timezone
from datetime import timedelta
from .models import UserGroup, MessagingGroup, Notification


@periodic_task(run_every=crontab(hour='*48/'))
def delete_dead_groups():
    '''
    Server Stored Procedure: deletes 'dead' (e.g. empty MessagingGroups) every 48 hours
    :return: null
    '''
    try:
        MessagingGroup.objects.exclude(id__in=UserGroup.objects.all().values_list('group', flat=True).distinct()).delete()
    except:
        # log here
        pass


@periodic_task(run_every=crontab(hour='*48/'))
def delete_dead_groups():
    '''
    Server Stored Procedure: deletes read Notifications with a timestamp from > 2 days ago every 48 hours
    :return: null
    '''
    try:
        Notification.objects.filter(read=1, timestamp__lt=timezone.now().astimezone()-2).delete()
    except:
        # log here
        pass
