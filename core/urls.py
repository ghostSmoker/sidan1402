from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include
from .views import RegisterAPIView,LoginAPIView, UserAPIView,RefreshAPIVeiw,LogoutAPIVeiw , FormAPIView,UserProfileView,UserUpdateView,FormHistoryView,ChangePasswordView,Dashboard,GenerateAPI,FormUpdateView,ForgetPasswordView,SubscriptionCreateAPIView

urlpatterns = [
    path('register',RegisterAPIView.as_view()),
    path('login',LoginAPIView.as_view()),
    path('user',UserAPIView.as_view()),
    path('refresh',RefreshAPIVeiw.as_view()),
    path('logout',LogoutAPIVeiw.as_view()),
    path('form/<int:pk>/',FormAPIView.as_view()),
    path('profile/<int:pk>/',UserProfileView.as_view()),
    path('update/<int:pk>/',UserUpdateView.as_view()),
    path('history/<int:user_id>/',FormHistoryView.as_view()),
    path('updatehistory/<int:user_id>/<int:bill_id>/',FormUpdateView.as_view()),
    path('changepass/<int:user_id>/', ChangePasswordView.as_view(), name='change_password'),
    path('forgetpass/', ForgetPasswordView.as_view()),
    path('subscribe/<int:user_id>/', SubscriptionCreateAPIView.as_view()),
    path('Dashboard/<int:pk>/', Dashboard.as_view(), name='Dashboard'),
    path('generate/<int:pk>/',GenerateAPI.as_view())
]

urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)