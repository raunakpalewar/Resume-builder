# Generated by Django 4.1.13 on 2024-09-30 16:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='personaldetails',
            name='abstract',
            field=models.TextField(blank=True, null=True),
        ),
    ]
