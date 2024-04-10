from django.db import models
from django.contrib.auth.models import AbstractBaseUser,BaseUserManager,PermissionsMixin
from django.utils import timezone

class CustomUserManager(BaseUserManager):
    def _create_user(self,email,password,**extra_fields):
        if not email:
            return ValueError("Please Enter Email Properly")
    
        email=self.normalize_email(email)
        user=self.model(email=email,**extra_fields)
        user.set_password(password)
        user.save(using=self.db)
        return user
    
    def create_user(self,email=None,password=None,**extra_fields):
        extra_fields.setdefault('is_staff',False)
        extra_fields.setdefault('is_superuser',False)
        return self._create_user(email,password,**extra_fields)
    
    def create_superuser(self,email=None,password=None,**extra_fields):
        extra_fields.setdefault('is_staff',True)
        extra_fields.setdefault('is_superuser',True)
        return self._create_user(email,password,**extra_fields)



class User(AbstractBaseUser,PermissionsMixin):
    email=models.EmailField(unique=True)
    password=models.CharField(max_length=255,null=True,blank=True)
    is_staff=models.BooleanField(default=False)
    is_active=models.BooleanField(default=True)
    # role=models.CharField(null=True,blank=True,choices=(('user',"User")),max_length=255)
    date_joined = models.DateTimeField(auto_now_add=True)

    objects=CustomUserManager()
    USERNAME_FIELD='email'
    REQUIRED_FIELDS=[]  
    
    def __str__(self):
        return f"{self.email}"

class PersonalDetails(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    mobile_number = models.CharField(max_length=20, blank=True, null=True)
    address = models.CharField(max_length=255, blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)
    hobbies = models.CharField(max_length=255, blank=True, null=True)
    linkedin = models.TextField(blank=True, null=True)
    github = models.TextField(blank=True, null=True)
    personal_website = models.TextField(blank=True, null=True)
    abstract=models.TextField()
    language_known=models.TextField(null=True,blank=True)
    
    def __str__(self):
        return f'Personal details of {self.user.email}'

class Education(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    degree = models.CharField(max_length=100)
    specialization=models.CharField(max_length=255)
    institution = models.CharField(max_length=100)
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    grade=models.IntegerField()

class WorkExperience(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    company = models.CharField(max_length=100)
    position = models.CharField(max_length=100)
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    description=models.TextField(null=True,blank=True)
    location=models.CharField(max_length=255,null=True,blank=True)

class Skill(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    skill_name = models.CharField(max_length=100)
    proficiency = models.CharField(max_length=100,null=True,blank=True)

class Project(models.Model):
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    project_name=models.CharField(max_length=255)
    project_description=models.TextField()
    project_link=models.URLField(null=True,blank=True)
    date=models.DateField(null=True,blank=True)
    
class Certificate(models.Model):
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    certification_name=models.CharField(max_length=255)
    source=models.CharField(max_length=255,null=True,blank=True)
    certificate_link=models.URLField(null=True,blank=True)

class Achievement(models.Model):
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    achievment_description=models.TextField()
    date = models.DateField(null=True, blank=True)

