from django.urls import path
from rest_framework.authtoken import views as rest
from messaging import views

''' API Endpoint Routing '''

urlpatterns = [
    # Auth
    path('api-token-auth/', views.CustomObtainAuthToken.as_view()),
    # UserList
    path('user/', views.UserList.as_view({'get': 'controller', 'post': 'controller'})),
    path('user/search/<str:q>', views.UserList.as_view({'get': 'search_user'})),
    # UserDetail
    path('user/<int:pk>', views.UserDetail.as_view()),
    # MessageList
    path('message/', views.MessageList.as_view({'get': 'master_list'})),
    path('message/user/<int:pk>', views.MessageList.as_view({'get': 'user_list'})),
    path('message/group/<int:pk>', views.MessageList.as_view({'get': 'group_list'})),
    path('message/user/', views.MessageList.as_view({'post': 'post_user_message'})),
    path('message/group/', views.MessageList.as_view({'post': 'post_group_message'})),
    # MessageDetail
    path('message/<int:pk>', views.MessageDetail.as_view()),
    # UserMessageList
    path('message/user/<int:pk>/user/<int:pk2>', views.UserMessageList.as_view()),
    # GroupMessageList
    path('message/group/<int:pk>/user/<int:pk2>', views.GroupMessageList.as_view()),
    # MessagingGroupList
    path('group/', views.MessagingGroupList.as_view()),
    # MessagingGroupDetail
    path('group/<int:pk>', views.MessagingGroupDetail.as_view()),
    # UserGroupList
    path('user/group/', views.UserGroupList.as_view()),
    # UserGroupDetail
    path('user/<int:pk>/group/<int:pk2>', views.UserGroupDetail.as_view()),
    # UserInboxList
    path('inbox/<int:pk>', views.UserInboxList.as_view()),
    # GroupInboxList
    path('inbox/group/<int:pk>', views.GroupInboxList.as_view()),
    # PollingList
    path('poll/user/<int:pk>/<int:pk2>/<int:last_id>', views.PollingList.as_view({'get': 'poll_user_message'})),
    path('poll/group/<int:pk>/<int:last_id>', views.PollingList.as_view({'get': 'poll_group_message'})),
    path('poll/notification/', views.PollingList.as_view({'get': 'poll_notifications'})),
    # NotificationList
    path('notification/<int:pk>', views.NotificationList.as_view()),
    # HelpUtil
    path('help/', views.HelpUtil.as_view())
]
