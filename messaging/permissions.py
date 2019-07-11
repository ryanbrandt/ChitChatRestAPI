from rest_framework import permissions
from messaging.models import UserGroup


# global utility; defines if user is in a MessagingGroup instance
def in_group(request, view, obj=None):
    try:
        if not obj:
            UserGroup.objects.get(user=request.user, group=view.kwargs['pk'])
        else:
            if request.user.id != obj['author']:
                return False
            UserGroup.objects.get(user=obj['author'], group=obj['group'])
        return True
    except UserGroup.DoesNotExist:
        return False


'''
Custom User Read/Write Permissions
    -Restricts Master User List to Staff 
    -Restricts Users from manipulating other Users Data
'''
class UserReadWrite(permissions.BasePermission):

    def has_permission(self, request, view):
        # Admin only for master lists, anyone can post (create new account, group, etc.)
        if request.method == 'POST':
            return True
        elif request.method == 'GET' and not view.kwargs:
            return request.user.is_staff
        return request.user.is_authenticated

    # user can only retrieve and manipulate owned user data
    def has_object_permission(self, request, view, obj):
        return request.user == obj


'''
Custom Message Read/Write Permissions
    -Restricts Master Message List to staff
    -Restricts User Message List to User whose list is requested
    -Restricts Group Message List to MessagingGroup members
    -Validates User posting User/Group Message is User requesting & is in MessagingGroup
'''
class MessageReadWrite(permissions.BasePermission):

    def has_permission(self, request, view):
        try:
            # Admin only
            if view.action == 'master_list':
                return request.user.is_staff
            # Only user can request their own messages
            elif view.action == 'user_list':
                return request.user.id == view.kwargs['pk']
            # User must be in group to request group messages
            elif view.action == 'group_list':
                return in_group(request, view)
        except AttributeError:
            return True
        return True

    def has_object_permission(self, request, view, obj):
        try:
            # User must be user posting to post a message
            if view.action == 'post_user_message':
                return True
            # User must be in group to post to group and be user posting
            elif view.action == 'post_group_message':
                # FIXME
                return True
        except AttributeError:
            # From MessageDetail, user can only retrieve/delete messages they own
            if request.method == 'GET' or request.method == 'DELETE':
                return request.user == obj.author


'''
Custom UserMessage Read/Write Permissions
    -Restricts User not in a UserMessage thread from requesting thread
    -Restricts User not owner of an Inbox from requesting Inbox
'''
class UserMessageRead(permissions.BasePermission):

    def has_permission(self, request, view):
        # User can only read thread if a participant/only read inbox if owner
        try:
            if request.user.id == view.kwargs['pk'] or request.user.id == view.kwargs['pk2']:
                return True
        # pk2 DNE for InboxList call
        except KeyError:
            return request.user.id == view.kwargs['pk']


'''
Custom MessagingGroup Read/Write Permissions
    -Restricts Users not in MessagingGroup from retrieving/manipulating group data
'''
class GroupReadWrite(permissions.BasePermission):

    def has_permission(self, request, view):
        return in_group(request, view)


'''
Custom UserGroup Write Permissions
    -Restricts User from deleting an instance of UserGroup they are not related to
'''
class UserGroupWrite(permissions.BasePermission):

    def has_object_permission(self, request, view, obj):
        return request.user == obj.user
