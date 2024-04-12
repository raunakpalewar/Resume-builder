from django.contrib import admin
from .models import *

# Register your models here.
admin.site.register(User)
admin.site.register(Education)
admin.site.register(WorkExperience)
admin.site.register(Skill)
admin.site.register(Project)
admin.site.register(Certificate)
admin.site.register(Achievement)
admin.site.register(PersonalDetails)