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
    path('user_registration/', views.UserRegistration.as_view()),
    path('login/', views.Login.as_view()),
    path('logout/', views.UserLogout.as_view()),
    path('forgotPassword/', views.ForgotPassword.as_view()),
   #  path("resetPassword/<str:uidb64>/<str:token>/", views.ResetPassword.as_view()),
    path("resetPassword/<str:email>/<str:secret_code>/", views.ResetPassword.as_view()),


    path('addPersonalDetails/', views.AddPersonalDetails.as_view()),
    path('getPersonalDetails/', views.GetPersonalDetails.as_view()),
    path('updatePersonalDetails/', views.UpdatePersonalDetails.as_view()),
    path('deletePersonalDetails/', views.DeletePersonalDetails.as_view()),
    
    
    path('addEducation/', views.AddEducation.as_view()),
    path('getEducation/', views.GetEducation.as_view()),
    path('updateEducation/<str:degree>/', views.UpdateEducation.as_view()),
    path('deleteEducation/<str:degree>/', views.DeleteEducation.as_view()),
    
    
    path('addExperience/', views.AddExperience.as_view()),
    path('getExperience/', views.GetExperience.as_view()),
    path('updateExperience/<str:company>/', views.UpdateExperience.as_view()),
    path('deleteExperience/<str:company>/', views.DeleteExperience.as_view()),
    
    
    path('addSkill/', views.AddSkill.as_view()),
    path('getSkill/', views.GetSkill.as_view()),
    path('updateSkill/<str:skill_name>/', views.UpdateSkill.as_view()),
    path('deleteSkill/<str:skill_name>/', views.DeleteSkill.as_view()),
    
    
    path('addCertificate/', views.AddCertificate.as_view()),
    path('getCertificate/', views.GetCertificate.as_view()),
    path('updateCertificate/<str:certification_name>', views.UpdateCertificate.as_view()),
    path('deleteCertificate/<str:certification_name>/', views.DeleteCertificate.as_view()),
    
    
    path('addAchievement/', views.AddAchievement.as_view()),
    path('getAchievement/', views.GetAchievement.as_view()),
    path('updateAchievement/<str:achievment_description>/', views.UpdateAchievements.as_view()),
    path('deleteAchievement/<str:achievment_description>/', views.DeleteAchievements.as_view()),
    
    
    path('getAllDetails/', views.GetAllDetails.as_view()),
    path('analyseData/', views.AnalyseData.as_view()),
    path('exportResume/', views.ExportResume.as_view()),
    
    path('addProject/', views.AddProject.as_view()),
    path('getProjects/', views.GetProjects.as_view()),
    path('updateProject/<str:project_name>/', views.UpdateProject.as_view()),
    path('deleteProject/<str:project_name>/', views.DeleteProject.as_view()),
    
    path('htmlformat/', views.render_page, name='htmlformat'),
    path('render_page_Data/', views.render_page_data, name='render_page_Data'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
