# Generated by Django 4.1.13 on 2024-04-15 14:20

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('email', models.EmailField(max_length=254, unique=True)),
                ('password', models.CharField(blank=True, max_length=255, null=True)),
                ('is_staff', models.BooleanField(default=False)),
                ('is_active', models.BooleanField(default=True)),
                ('date_joined', models.DateTimeField(auto_now_add=True)),
                ('secret_code', models.CharField(blank=True, max_length=255, null=True, unique=True)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='WorkExperience',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('company', models.CharField(max_length=100)),
                ('position', models.CharField(max_length=100)),
                ('start_date', models.DateField()),
                ('end_date', models.DateField(blank=True, null=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('location', models.CharField(blank=True, max_length=255, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Skill',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('skill_name', models.CharField(max_length=100)),
                ('proficiency', models.CharField(blank=True, max_length=100, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Project',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('project_name', models.CharField(max_length=255)),
                ('project_description', models.TextField()),
                ('project_link', models.URLField(blank=True, null=True)),
                ('date', models.DateField(blank=True, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='PersonalDetails',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('full_name', models.CharField(blank=True, max_length=255, null=True)),
                ('email_id', models.EmailField(blank=True, max_length=254, null=True)),
                ('mobile_number', models.CharField(blank=True, max_length=20, null=True)),
                ('address', models.CharField(blank=True, max_length=255, null=True)),
                ('date_of_birth', models.DateField(blank=True, null=True)),
                ('hobbies', models.CharField(blank=True, max_length=255, null=True)),
                ('linkedin', models.TextField(blank=True, null=True)),
                ('github', models.TextField(blank=True, null=True)),
                ('personal_website', models.TextField(blank=True, null=True)),
                ('abstract', models.TextField()),
                ('language_known', models.TextField(blank=True, null=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Education',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('degree', models.CharField(max_length=100)),
                ('specialization', models.CharField(blank=True, max_length=255, null=True)),
                ('institution', models.CharField(max_length=100)),
                ('university', models.CharField(blank=True, max_length=255, null=True)),
                ('end_date', models.DateField(blank=True, null=True)),
                ('percent', models.CharField(blank=True, max_length=255, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Certificate',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('certification_name', models.CharField(max_length=255)),
                ('source', models.CharField(blank=True, max_length=255, null=True)),
                ('certificate_link', models.URLField(blank=True, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Achievement',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('achievment_description', models.TextField()),
                ('date', models.DateField(blank=True, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
