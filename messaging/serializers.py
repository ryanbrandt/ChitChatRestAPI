from rest_framework import serializers
from messaging.models import ExtendedUser, UserGroup, MessagingGroup, Message, UserMessage, GroupMessage, Notification

''' Serializer for OOB User Model; supports serialization for creation & update'''
class ExtendedUserSerializer(serializers.ModelSerializer):


    class Meta:
        model = ExtendedUser
        fields = ['id', 'username', 'password', 'phone', 'is_public']

    ''' @override: must call create_user for authorization token system to function appropriately '''
    def create(self, validated_data):
        new_user = ExtendedUser.objects.create_user(**validated_data)
        return new_user


''' Safe ExtendedUser Serializer; just get identifying fields '''
class SafeExtendedUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = ExtendedUser
        fields = ['id', 'username']


''' Serializer for UserGroup Model; Used in reverse relationship with MessagingGroupSerializer '''
class NestedGroupSerializer(serializers.ModelSerializer):
    username = serializers.SlugRelatedField(source='user', slug_field='username', queryset=ExtendedUser.objects.all())

    class Meta:
        model = UserGroup
        fields = ['user_id', 'username']


''' Serializer for MessagingGroup Model '''
class MessagingGroupSerializer(serializers.ModelSerializer):
    users = NestedGroupSerializer(source='in_group', many=True, read_only=True)

    class Meta:
        model = MessagingGroup
        fields = ['id', 'name', 'users']


''' Serializer for base Message Model; used to implement UserMessageSerializer and GroupMessageSerializer '''
class MessageSerializer(serializers.ModelSerializer):
    author = serializers.SlugRelatedField(slug_field='username', read_only=True)
    author_id = serializers.SlugRelatedField(source='author', slug_field='id', queryset=ExtendedUser.objects.all())

    class Meta:
        model = Message
        fields = ['author_id', 'author', 'content', 'timestamp']


''' 
    Serializer for UserMessage Model; contains nested MessageSerializer instance to model relationship
        e.g. {'user_recipient: ... , 'message': {'author_id': ... } }
 '''
class UserMessageSerializer(serializers.ModelSerializer):
    message = MessageSerializer()
    recipient_id = serializers.PrimaryKeyRelatedField(source='user', queryset=ExtendedUser.objects.all())
    recipient = serializers.SlugRelatedField(source='user', slug_field='username', read_only=True)

    class Meta:
        model = UserMessage
        fields = ['id', 'recipient_id', 'recipient', 'message']

    ''' @override: must manually create Message instance to then associate it with UserMessage instance '''
    def create(self, validated_data):
        new_message = Message.objects.create(**(validated_data.pop('message')))
        new_user_message = UserMessage.objects.create(message=new_message, user=validated_data.pop('user'))
        return new_user_message


'''
    Serializer for GroupMessage Model; contains nested MessageSerializer instance to model relationship
        e.g. {'group': ... , 'message': {'author': ... } }
'''
class GroupMessageSerializer(serializers.ModelSerializer):
    message = MessageSerializer()
    group_id = serializers.PrimaryKeyRelatedField(source='group', queryset=MessagingGroup.objects.filter())
    group = serializers.SlugRelatedField(slug_field='name', read_only=True)

    class Meta:
        model = GroupMessage
        fields = ['id', 'group_id', 'group', 'message']

    ''' @override: must manually create Message instance to then associate it with GroupMessage instance '''
    def create(self, validated_data):
        new_message = Message.objects.create(**(validated_data.pop('message')))
        new_group_message = GroupMessage.objects.create(message=new_message, group=validated_data.pop('group'))
        return new_group_message


''' Serializer for UserGroup POSTs and DELETEs, provides some more relevant info on POST '''
class UserGroupSerializer(serializers.ModelSerializer):
    username = serializers.SlugRelatedField(source='user', slug_field='username', read_only=True)
    group_name = serializers.SlugRelatedField(source='group', slug_field='name', read_only=True)

    class Meta:
        model = UserGroup
        fields = ['user', 'group', 'username', 'group_name']


''' Simple Notification serializer '''
class NotificationSerializer(serializers.ModelSerializer):

    class Meta:
        model = Notification
        fields = ['activity_type', 'source_id', 'timestamp', 'read', 'details']