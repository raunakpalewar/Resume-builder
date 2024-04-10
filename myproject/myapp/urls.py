from django.urls import path,re_path
from django.conf.urls.static import static
from django.conf import settings
from .import views
from django.urls import re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from .import views



schema_view = get_schema_view(
   openapi.Info(
      title="Resume Builder Apis",
      default_version='r1',
      description="For Resume Builder",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="contact@snippets.local"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)


urlpatterns = [
    path('', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('user_registration',views.UserRegistration.as_view()),
    path('login/',views.Login.as_view()),
    path('logout/',views.UserLogout.as_view()),
    path('forgotPassword/',views.ForgotPassword.as_view()),
   #  path('resetPassword/',views.ResetPassword.as_view()),
   path("resetPassword/<str:uidb64>/<str:token>/", views.ResetPassword.as_view()),
   path('addPersonalDetails/', views.AddPersonalDetails.as_view()),
    path('getPersonalDetails/', views.GetPersonalDetails.as_view()),
    path('updatePersonalDetails/<str:email>/', views.UpdatePersonalDetails.as_view()),
    path('deletePersonalDetails/<str:email>/', views.DeletePersonalDetails.as_view()),



    
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)