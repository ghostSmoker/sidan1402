# Generated by Django 4.1.7 on 2023-06-02 12:42

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0012_bill_cdcd'),
    ]

    operations = [
        migrations.CreateModel(
            name='BillHistory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('uuid', models.CharField(max_length=255)),
                ('refrenceId', models.CharField(max_length=255)),
                ('taxid', models.CharField(max_length=255)),
                ('sendTime', models.CharField(max_length=255)),
                ('user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.DeleteModel(
            name='Dashboard',
        ),
    ]