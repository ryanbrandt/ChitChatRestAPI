from django.http import HttpResponse, JsonResponse
from rest_framework.views import APIView
from rest_framework.parsers import JSONParser
from rest_framework import viewsets, permissions
from rest_framework.authentication import TokenAuthentication
from django.http import Http404
from django.db.models import Q
from messaging.models import ExtendedUser, UserGroup, MessagingGroup, Message, UserMessage, GroupMessage, Notification
from messaging.serializers import ExtendedUserSerializer, UserGroupSerializer, MessagingGroupSerializer, MessageSerializer, GroupMessageSerializer, UserMessageSerializer, SafeExtendedUserSerializer, NotificationSerializer
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from messaging.permissions import UserReadWrite, MessageReadWrite, UserMessageRead, GroupReadWrite, UserGroupWrite
import time
import yagmail

''' @override: overrides DRF ObtainAuthToken method to return User token and User Id '''
class CustomObtainAuthToken(ObtainAuthToken):

    def post(self, request, *args, **kwargs):
        response = super(CustomObtainAuthToken, self).post(request, *args, **kwargs)
        token = Token.objects.get(key=response.data['token'])
        return Response({'token': token.key, 'id': token.user_id})


class UserList(viewsets.GenericViewSet):
    # TODO: fix this vulnerability, need to override at post else 401, no perm/auth = anyone access user list though
    authentication_classes = [TokenAuthentication]
    permission_classes = (UserReadWrite,)

    def controller(self, request):
        if request.method == 'GET':
            return self.get_all(request)
        else:
            return self.post_user(request)

    def get_all(self, request):
        '''
        Endpoint: api/user/
        Use Cases: Get all ExtenedUser instances
        :param request: HttpRequest object
        :return:
            JsonResponse: list of all Users and status 200
            Http403: status 403 if not authorized (User requesting is not staff/bad token)
        '''
        users = ExtendedUser.objects.all()
        serialized = SafeExtendedUserSerializer(users, many=True)
        return JsonResponse(serialized.data, safe=False, status=200)

    def search_user(self, request, q):
        '''
        Endpoint: api/user/{string: q}
        Use Cases: provides User lookup functionality; search based on username
        :param request: HttpRequest object
        :param q: Query value for LIKE %q%
        :return:
            JsonResponse: Users matching query and status 200
            Http404: status 404 if not found
            Http403: status 403, unauthorized if not logged in
        '''
        try:
            users_like = ExtendedUser.objects.get((Q(username__icontains=q) | Q(phone__contains=q)) & Q(is_public=1))
            serialized = SafeExtendedUserSerializer(users_like)
            return JsonResponse(serialized.data, status=200)
        except Exception as e:
            if type(e).__name__=='MultipleObjectsReturned':
                users_like = ExtendedUser.objects.filter((Q(username__icontains=q) | Q(phone__contains=q)) & Q(is_public=1))
                serialized = SafeExtendedUserSerializer(users_like, many=True)
                return JsonResponse(serialized.data, safe=False, status=200)
            raise Http404


    def post_user(self, request):
        '''
        Endpoint: api/user/
        Use Cases: Create a new ExtendedUser instance
        :param request: HttpRequest object
        :return:
            JsonResponse:
                newly created User and status 201
                status 400 on client error and erros
        '''
        data = JSONParser().parse(request)
        serialized = ExtendedUserSerializer(data=data)
        if serialized.is_valid():
            serialized.save()
            return JsonResponse(serialized.data, status=201)
        return JsonResponse(serialized.errors, status=400)


class UserDetail(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (permissions.IsAuthenticated, UserReadWrite)

    def get_user(self, pk):
        try:
            return ExtendedUser.objects.get(id=pk)
        except ExtendedUser.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        '''
        Endpoint: api/user/{pk}
        Use Cases: Get User identified by pk
        :param request: HttpRequest object
        :param pk: User primary key
        :return:
            JsonResponse: User requested and status 200
            Http404: status 404 if User not found
            Http403: status 403 if unauthorized (User requesting is not User identified by pk/bad token)
        '''
        user = self.get_user(pk)
        self.check_object_permissions(request, user)
        serialized = ExtendedUserSerializer(user)
        return JsonResponse(serialized.data, status=200)

    def put(self, request, pk):
        '''
        Endpoint: api/user/{pk}
        Use Cases: Update User identified by pk
        :param request: HttpRequest object
        :param pk: User primary key
        :return:
            JsonResponse:
                newly update User and status 200
                status 400 on client error and errors
            Http404: status 404 on User not found
            Http403: status 403 on unauthorized (User requesting nor User identified by pk/bad token)
        '''
        user = self.get_user(pk)
        self.check_object_permissions(request, user)
        data = JSONParser().parse(request)
        serialized = ExtendedUserSerializer(user, data=data)
        if serialized.is_valid():
            serialized.save()
            return JsonResponse(serialized.data, status=200)
        return JsonResponse(serialized.errors, status=400)

    def patch(self, request, pk):
        '''
        Endpoint: api/user/{pk}
        Use Cases: Partially update update User identified by pk
        :param request: HttpRequest object
        :param pk: User primary key
        :return:
            JsonResponse:
                newly updated User and status 200
                status 400 on client error and errors
            Http404: status 404 on User not found
            Http403: status 403 on unauthorized (User requesting nor User identified by pk/bad token)
        '''
        user = self.get_user(pk)
        self.check_object_permissions(request, user)
        data = JSONParser().parse(request)
        serialized = ExtendedUserSerializer(user, data=data, partial=True)
        if serialized.is_valid():
            serialized.save()
            return JsonResponse(serialized.data, status=200)
        return JsonResponse(serialized.errors, status=400)

    def delete(self, request, pk):
        '''
        Endpoint: api/user/{pk}
        :param request: HttpRequest object
        :param pk: User primary key
        :return:
            HttpResponse: status 204, empty
            Http404: status 404 on not found
            Http403: status 403 on unauthorized (if User requesting is not User identified by pk/bad token)
        '''
        user = self.get_user(pk)
        self.check_object_permissions(request, user)
        user.delete()
        return HttpResponse(status=204)


class MessageList(viewsets.GenericViewSet):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (permissions.IsAuthenticated, MessageReadWrite,)

    def get_messages(self, pk, is_group):
        if not is_group:
            authored_messages = Message.objects.filter(author=pk).values_list('id', flat=True)
            try:
                return UserMessage.objects.get(message__in=authored_messages)
            except Exception as e:
                if type(e).__name__ == 'MultipleObjectsReturned':
                    return UserMessage.objects.filter(message__in=authored_messages).order_by('-message__timestamp')
            return UserMessage.objects.none()

        else:
            authored_messages = Message.objects.filter(author=pk).values_list('id', flat=True)
            try:
                return GroupMessage.objects.get(message__in=authored_messages)
            except Exception as e:
                if type(e).__name__ == 'MultipleObjectsReturned':
                    return GroupMessage.objects.filter(message__in=authored_messages).order_by('-message__timestamp')
            return GroupMessage.objects.none()

    def master_list(self, request):
        '''
        Endpoint: api/message/
        Use Cases: Get all Message instances
        :param request: HttpRequest object
        :return:
            JsonResponse: all Message instances and status 200
            Http403: status 403 if unauthorized (User requesting not staff/bad token)
        '''
        user_messages = UserMessage.objects.all()
        group_messages = GroupMessage.objects.all()
        user_count = user_messages.count()
        group_count = group_messages.count()

        if user_count > 0 and group_count > 0:
            user_serialized = MessageSerializer(user_messages, many=True if user_count > 1 else False)
            group_serialized = GroupMessageSerializer(group_messages, many=True if group_count > 1 else False)
            return JsonResponse([user_serialized.data, group_serialized.data], safe=False, status=200)
        if user_count > 0:
            user_serialized = UserMessageSerializer(user_messages, many=True if user_count > 1 else False)
            return JsonResponse(user_serialized.data, safe=False, status=200)
        if group_count > 0:
            group_serialized = GroupMessageSerializer(group_messages, many=True if group_count > 1 else False)
            return JsonResponse(group_serialized.data, safe=False, status=200)
        raise Http404

    def user_list(self, request, pk):
        '''
        Endpoint: api/message/user/{pk}
        Use Cases: Get all Messages authored by a User
        :param request: HttpRequest object
        :param pk: User primary key
        :return:
            JsonResponse: all Message instances authored by User identified by pk and status 200
            Http404: status 404 if not found
            Http403: status 403 if unauthorized (User requesting not User identified by pk/bad token)
        '''
        user_messages = self.get_messages(pk, False)
        group_messages = self.get_messages(pk, True)
        user_count = user_messages.count()
        group_count = group_messages.count()

        if user_count > 0 and group_count > 0:
            group_serialized = GroupMessageSerializer(group_messages, many=True if group_count > 1 else False)
            user_serialized = UserMessageSerializer(user_messages, many=True if user_count > 1 else False)
            return JsonResponse([user_serialized.data, group_serialized.data], safe=False, status=200)
        if user_count > 0:
            user_serialized = UserMessageSerializer(user_messages, many=True if user_count > 1 else False)
            return JsonResponse(user_serialized.data, safe=False, status=200)
        if group_count > 0:
            group_serialized = GroupMessageSerializer(group_messages, many=True if group_count > 1 else False)
            return JsonResponse(group_serialized.data, safe=False, status=200)
        raise Http404

    def group_list(self, request, pk):
        '''
        Endpoint: api/message/group/{pk}
        Use Cases: Get all Messages owned by a MessagingGroup
        :param request: HttpRequest object
        :param pk: MessagingGroup primary key
        :return:
            JsonResponse: all Messages owned by MessagingGroup and status 200
            Http404: status 404 on not found
            Http403: status 403 on unauthorized (User requesting not in MessagingGroup/bad token)
        '''
        try:
            group_messages = GroupMessage.objects.get(group=pk)
            serialized = GroupMessageSerializer(group_messages)
            return JsonResponse(serialized.data, status=200)
        except Exception as e:
            if type(e).__name__ == 'MultipleObjectsReturned':
                group_messages = GroupMessage.objects.filter(group=pk).order_by('message__timestamp')
                serialized = GroupMessageSerializer(group_messages, many=True)
                return JsonResponse(serialized.data, safe=False, status=200)
        raise Http404

    def post_user_message(self, request):
        '''
        Endpoint: api/message/user
        Use Cases: Post a new UserMessage instance
        :param request: HttpRequest object
        :return:
            JsonResponse:
                newly created UserMessage instance and status 201
                status 400 on client error and errors
            Http403: status 403 on unauthorized (User identified as author in body not User requesting/bad token)
        '''
        data = JSONParser().parse(request)
        self.check_object_permissions(request, data['message']['author_id'])
        serialized = UserMessageSerializer(data=data)
        if serialized.is_valid():
            serialized.save()
            return JsonResponse(serialized.data, status=201)
        return JsonResponse(serialized.errors, status=400)

    def post_group_message(self, request):
        '''
        Endpoint: api/message/group
        Use Cases: Post a new GroupMessage instance
        :param request: HttpRequest object
        :return:
            JsonResponse:
                newly created GroupMessage instance and status 201
                status 400 on client error and errors
            Http403: status 403 on unauthorized (User identified as author in body not User requesting/not in group/bad token)
        '''
        data = JSONParser().parse(request)
        self.check_object_permissions(request, {'group': data['group_id'], 'author': data['message']['author_id']})
        serialized = GroupMessageSerializer(data=data)
        if serialized.is_valid():
            serialized.save()
            return JsonResponse(serialized.data, status=201)
        return JsonResponse(serialized.errors, status=400)


class UserMessageList(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (permissions.IsAuthenticated, UserMessageRead)

    def get(self, request, pk, pk2):
        '''
        Endpoint: api/message/user/{pk}/user/{pk2}
        Use Cases: Fetch Messages between two Users
        :param request: HttpRequest object
        :param pk: first Users's primary key
        :param pk2: second User's primary key
        :return:
            JsonResponse: all shared Message instances between pk and pk2 and status 200
            Http404: status 404 on not found
            Http403: status 403 if unauthorized
        '''
        try:
            shared_msgs = UserMessage.objects.get(Q(user=pk, message__author=pk2) | Q(user=pk2, message__author=pk))
            serialized = UserMessageSerializer(shared_msgs)
            return JsonResponse(serialized.data, status=200)
        except Exception as e:
            if type(e).__name__ == 'MultipleObjectsReturned':
                shared_msgs = UserMessage.objects.filter(Q(user=pk, message__author=pk2) | Q(user=pk2, message__author=pk)).order_by('message__timestamp')
                serialized = UserMessageSerializer(shared_msgs, many=True)
                return JsonResponse(serialized.data, safe=False, status=200)
            raise Http404


class GroupMessageList(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (permissions.IsAuthenticated, GroupReadWrite)

    def get(self, request, pk, pk2):
        '''
        Endpoint: api/message/group/{pk}/user/{pk2}
        Use Cases: Fetch Messages sent by a User to a MessagingGroup
        :param request: HttpRequest object
        :param pk: MessagingGroup primary key
        :param pk2: User primary key
        :return:
            JsonResponse: all sent Message instances between User and MessagingGroup and status 200
            Http404: status 404 on not found
            Http403: status 403 if unauthorized (User DNE in MessagingGroup, bad token, etc)
        '''
        try:
            user_msgs_to_group = GroupMessage.objects.get(group=pk, message__author=pk2)
            serialized = GroupMessageSerializer(user_msgs_to_group)
            return JsonResponse(serialized.data, status=200)
        except Exception as e:
            if type(e).__name__ == 'MultipleObjectsReturned':
                user_msgs_to_group = GroupMessage.objects.filter(group=pk, message__author=pk2)
                serialized = GroupMessageSerializer(user_msgs_to_group, many=True)
                return JsonResponse(serialized.data, safe=False, status=200)
            raise Http404


class MessageDetail(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (permissions.IsAuthenticated, MessageReadWrite)

    def get_message(self, pk):
        try:
            return Message.objects.get(id=pk)
        except Message.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        '''
        Endpoint: api/message/{pk}
        Use Cases: Get a Message instance by it's primary key
        :param request: HttpRequest object
        :param pk: Message instance primary key
        :return:
            JsonResponse: Message instance and status 200
            Http404: status 404 on not found
            Http403: status 403 if unauthorized (User requesting does not own message)
        '''
        message = self.get_message(pk)
        self.check_object_permissions(request, message)
        try:
            user_message = UserMessage.objects.get(message=message.id)
            serialized = UserMessageSerializer(user_message)
        except UserMessage.DoesNotExist:
            try:
                group_message = GroupMessage.objects.get(message=message.id)
                serialized = GroupMessageSerializer(group_message)
            except GroupMessage.DoesNotExist:
                # all Messages are related to a UserMessage or GroupMessage
                raise Http404

        return JsonResponse(serialized.data, status=200)

    def delete(self, request, pk):
        '''
        Endpoint: api/message/{pk}
        Use Cases: Delete a message identified by it's primary key
        :param request: HttpRequest Object
        :param pk: Message instance primary key
        :return:
            HttpResponse: status 204, empty
            Http404: status 404 on not found
            Http403: status 403 if unauthorized (User requesting does not own message)
        '''
        message = self.get_message(pk)
        self.check_object_permissions(request, message)
        message.delete()
        return HttpResponse(status=204)


class MessagingGroupList(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (permissions.IsAuthenticated, UserReadWrite)

    def get(self, request):
        '''
        Endpoint: api/group/
        Use Cases: Fetch all MessagingGroup instances (includes members)
        :param request: HttpRequest object
        :return:
            JsonResponse: list of all MessagingGroups + members and status 200
            Http403: status 403 if unauthorized (User requesting is not staff)
        '''
        groups = MessagingGroup.objects.all()
        serialized = MessagingGroupSerializer(groups, many=True)
        return JsonResponse(serialized.data, safe=False, status=200)

    def post(self, request):
        '''
        Endpoint: api/group/
        Use Cases: Create a new MessagingGroup instance
        :param request: HttpRequest object
        :return:
            JsonResponse:
                Newly created MessagingGroup and status 201
                Status 400 and client errors on bad input
            Http403: status 403 on unauthorized (bad User token)
        '''
        data = JSONParser().parse(request)
        serialized = MessagingGroupSerializer(data=data)
        if serialized.is_valid():
            serialized.save()
            return JsonResponse(serialized.data, status=201)
        return JsonResponse(serialized.errors, status=400)


class MessagingGroupDetail(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def get_group(self, pk):
        try:
            return MessagingGroup.objects.get(id=pk)
        except MessagingGroup.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        '''
        Endpoint: api/group/{pk}
        Use Cases: Get MessagingGroup identified by pk
        :param request: HttpRequest object
        :param pk: MessagingGroup primary key
        :return:
            JsonResponse: requested MessagingGroup + members and status 200
            Http404: status 404 on not found
            Http403: status 403 on unauthorized (User requesting not in group/bad token)
        '''
        group = self.get_group(pk)
        serialized = MessagingGroupSerializer(group)
        return JsonResponse(serialized.data, status=200)

    def delete(self, request, pk):
        '''
        Endpoint: api/group/{pk}
        Use Cases: Delete MessagingGroup identified by pk
        :param request: HttpRequest object
        :param pk: MessagingGroup primary key
        :return:
            HttpResponse: status 204, empty
            Http404: status 404 on not found
            Http403: status 403 on unauthorized (User not in requested MessagingGroup/bad token)
        '''
        group = self.get_group(pk)
        group.delete()
        return HttpResponse(status=204)

    def put(self, request, pk):
        '''
        Endpoint: api/group/{pk}
        Use Cases: Update a MessagingGroup's data
        :param request: HttpRequest object
        :param pk: MessagingGroup primary key
        :return:
            JsonResponse:
                MessagingGroup with newly updated data + members and status 200
                status 400 on client error and errors
            Http404: status 404 on not found
            Http403: status 403 on unauthorized (User not in requested MessagingGroup/bad token)
        '''
        group = self.get_group(pk)
        data = JSONParser().parse(request)
        serialized = MessagingGroupSerializer(group, data=data)
        if serialized.is_valid():
            serialized.save()
            return JsonResponse(serialized.data, status=200)
        return JsonResponse(serialized.errors, status=400)

    def patch(self, request, pk):
        '''
        Endpoint: api/group/{pk}
        Use Cases: Partially update a MessagingGroup's data
        :param request: HttpRequest object
        :param pk: MessagingGroup primary key
        :return:
            JsonResponse:
                MessagingGroup with newly updated data + members and status 200
                status 400 on client error and errors
            Http404: status 404 on not found
            Http403: status 403 on unauthorized (User not in requested MessagingGroup/bad token)
        '''
        group = self.get_group(pk)
        data = JSONParser().parse(request)
        serialized = MessagingGroupSerializer(group, data=data, partial=True)
        if serialized.is_valid():
            serialized.save()
            return JsonResponse(serialized.data, status=200)
        return JsonResponse(serialized.errors, status=400)


class UserGroupList(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        '''
        Endpoint: api/user/group
        Use Cases: create a new UserGroup instance
        :param request: HttpRequest object
        :return:
            JsonResponse:
                newly created UserGroup instance and status 200
                status 400 on client errors and errors
            Http403: status 403 on unauthorized (Bad token)
        '''
        data = JSONParser().parse(request)
        serialized = UserGroupSerializer(data=data)
        if serialized.is_valid():
            serialized.save()
            return JsonResponse(serialized.data, status=201)
        return JsonResponse(serialized.errors, status=400)


class UserGroupDetail(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (permissions.IsAuthenticated, UserGroupWrite)

    def delete(self, request, pk, pk2):
        '''
        Endpoint: api/user/{pk}/group/{pk2}
        Use Cases: Delete and instance of UserGroup (remove User from MessagingGroup)
        :param request: HttpRequest object
        :param pk: User primary key
        :param pk2: MessagingGroup primary key
        :return:
            HttpResponse: status 204, empty
            Http404: status 400 on not found
            Http403: status 403 on unauthorized (User requesting not User in UserGroup instance/bad token)
        '''
        try:
            user_group = UserGroup.objects.get(user=pk, group=pk2)
            self.check_object_permissions(request, user_group)
            user_group.delete()
            return HttpResponse(status=204)
        except UserGroup.DoesNotExist:
            raise Http404


class UserInboxList(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (permissions.IsAuthenticated, UserMessageRead)

    def get_most_recent_msg(self, pk, pk2):
        try:
            most_recent = UserMessage.objects.get(Q(user=pk, message__author=pk2) | Q(user=pk2, message__author=pk))
            return most_recent
        except Exception as e:
            if type(e).__name__ == 'MultipleObjectsReturned':
                most_recent = UserMessage.objects.filter(Q(user=pk, message__author=pk2) | Q(user=pk2, message__author=pk)).order_by('-message__timestamp')[0]
                return most_recent
            raise Http404

    def get(self, request, pk):
        '''
        Endpoint: api/inbox/user/{pk}
        Use Cases: Simulates a User DM inbox; fetches most recent Message Instance for each "thread"
        :param request: HttpRequest object
        :param pk: User primary key
        :return:
            JsonResponse: most recent Message instances and status 200
            Http404: status 404 on not found (User has no "threads")
            Http403: status 403 on unauthorized (User requesting not User identified by pk/bad token)
        '''
        try:
            users_messaging = ExtendedUser.objects.get(
                Q(id__in=UserMessage.objects.filter(user=pk).values('message__author').distinct()) |
                Q(id__in=UserMessage.objects.filter(message__author=pk).values('user').distinct()))
            most_recent_msg = self.get_most_recent_msg(request.user.id, users_messaging.id)
            serialized = UserMessageSerializer(most_recent_msg)
            return JsonResponse(serialized.data, status=200)

        except Exception as e:
            if type(e).__name__ == 'MultipleObjectsReturned':
                users_messaging = ExtendedUser.objects.filter(
                    Q(id__in=UserMessage.objects.filter(user=pk).values('message__author').distinct()) |
                    Q(id__in=UserMessage.objects.filter(message__author=pk).values('user').distinct()))

                # FIXME: this is horrendous, definitely not scalable
                most_recent_msg = UserMessage.objects.none()
                for user in users_messaging:
                    tmp = self.get_most_recent_msg(request.user.id, user.id)
                    instance = UserMessage.objects.filter(id=tmp.id)
                    most_recent_msg |= instance

                serialized = UserMessageSerializer(most_recent_msg.order_by('-message__timestamp'), many=True)
                return JsonResponse(serialized.data, safe=False, status=200)

        raise Http404


class GroupInboxList(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (permissions.IsAuthenticated, UserMessageRead)

    def get_most_recent_msg(self, group):
        try:
            most_recent = GroupMessage.objects.get(group=group)
            return most_recent
        except Exception as e:
            if type(e).__name__ == 'MultipleObjectsReturned':
                most_recent = GroupMessage.objects.filter(group=group).order_by('-message__timestamp')[0]
                return most_recent
            raise Http404

    def get(self, request, pk):
        '''
        Endpoint: api/inbox/group/{pk}
        Use Cases: Simulates a User's GroupMessage inbox; fetches most recent Message Instance for each MessagingGroup User belongs to
        :param request: HttpRequest object
        :param pk: User primary key
        :return:
            JsonResponse: most recent GroupMessage instances associated with MessagingGroups User belongs to and status 200
            Http404: status 404 on not found (User in no MessagingGroups)
            Http403: status 403 on unauthorized (User requesting not User identified by pk/bad token)
        '''

        try:
            groups_in = UserGroup.objects.get(user=pk)
            most_recent_msg = self.get_most_recent_msg(groups_in.group)
            serialized = GroupMessageSerializer(most_recent_msg)
            return JsonResponse(serialized.data, status=200)

        except Exception as e:
            if type(e).__name__ == 'MultipleObjectsReturned':
                groups_in = list(UserGroup.objects.filter(user=pk).values_list('group_id', flat=True))
                # FIXME: same issue, this wont scale well
                most_recent_msg = GroupMessage.objects.none()
                for group in groups_in:
                    tmp = self.get_most_recent_msg(group)
                    instance = GroupMessage.objects.filter(id=tmp.id)
                    most_recent_msg |= instance

                serialized = GroupMessageSerializer(most_recent_msg.order_by('-message__timestamp'), many=True)
                return JsonResponse(serialized.data, safe=False, status=200)

        raise Http404


class NotificationList(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, pk):
        '''
        Endpoint: api/notification/{pk}
        Use Cases: GET all notification objects owned by ExtendedUser identified by pk
        :param request: HttpRequest object
        :param pk: User primary key
        :return:
            JsonResponse: all Notification instances owned by pk, status 200
            Http404: status 404 if none found
            Http403: status 403 if unauthorized
        '''
        try:
            user_notifications = Notification.objects.get(user=pk)
            serialized = NotificationSerializer(user_notifications)
            return JsonResponse(serialized.data, status=200)
        except Exception as e:
            if type(e).__name__ == 'MultipleObjectsReturned':
                user_notifications = Notification.objects.filter(user=pk).order_by('-timestamp')
                serialized = NotificationSerializer(user_notifications, many=True)
                return JsonResponse(serialized.data, safe=False, status=200)
        raise Http404

    def patch(self, request, pk):
        '''
        Endpoint: api/notification/{pk}
        Use Cases: PATCH all Notification objects owned by ExtendedUser identified by pk; this utility just patches Notification.read = 1
        :param request: HttpRequest Object
        :param pk: User primary key
        :return:
            Http200: status 200 on success
            Http404: status 404 if no Notifications exist (should never land here)
            Http403: status 403 if unauthorized
        '''
        try:
            Notification.objects.filter(user=pk, read=0).update(read=1)
            return HttpResponse(status=200)
        except:
            raise Http404

    def delete(self, request, pk):
        '''
        Endpoint: api/notification/{pk}
        Use Cases: DELETE all read notifications owned by ExtendedUser identified by pk
        :param request: HttpRequest object
        :param pk: User primary key
        :return:
            Http204: status 204 on success
            Http403: status 403 on unauthorized
        '''
        try:
            Notification.objects.filter(user=pk, read=1).delete()
            return HttpResponse(status=204)
        except:
            raise Http404


class PollingList(viewsets.GenericViewSet):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def poll_user_message(self, request, pk, pk2, last_id):
        '''
        Endpoint: api/poll/user/{pk}/{pk2}/{last_id}
        Use Cases: long polling of UserMessage objects
        :param request: HttpRequest object
        :param pk: primary key of either User
        :param pk2: primary key of other User
        :param last_id: last UserMessage id seen
        :return:
            JsonResponse: status true and 200 if polling finds new instance, else status false
        '''
        for i in range(10):
            if(UserMessage.objects.filter((Q(message__author=pk, user=pk2) | Q(message__author=pk2, user=pk)) & Q(id__gt=last_id))):
                return JsonResponse({'status': True}, status=200)
            time.sleep(1)
        return JsonResponse({'status': False}, status=200)

    def poll_group_message(self, request, pk, last_id):
        '''
        Endpoint: api/poll/group/{pk}/{last_id}
        Use Cases: long polling of GroupMessage objects
        :param request: HttpRequest object
        :param pk: primary key of group
        :param last_id: last GroupMessage id seen
        :return:
            JsonResponse: status true and 200 if polling finds new instance, else status false
        '''
        for i in range(10):
            if(GroupMessage.objects.filter(group=pk, id__gt=last_id)):
                return JsonResponse({'status': True}, status=200)
            time.sleep(1)
        return JsonResponse({'status': False}, status=200)

    def poll_notifications(self, request):
        '''
        Endpoint: api/poll/notifications/
        Use Cases: long polling of Notification objects
        :param request: HttpRequest object
        :return: null
        '''
        for i in range(30):
            if Notification.objects.filter(user=request.user):
                return JsonResponse({'status': True}, status=200)
            time.sleep(1)
        return JsonResponse({'status': False}, status=200)


class HelpUtil(APIView):

    def post(self, request):
        '''
        Endpoint: api/help/
        Use Cases: Send email from submitted 'contact us' form
        :param request: HttpRequest object
        :return:
            HttpResponse: status 201 on email success, 500 on failure
        '''
        data = JSONParser().parse(request)
        try:
            yag = yagmail.SMTP('ryan.brandt1996')
            yag.send(subject=f"ChitChat Support: {data['subject']} ---- Return: {data['user']}", contents=data['contents'])
            return HttpResponse(status=201)
        except Exception as e:
            print(e)
            return HttpResponse(status=500)