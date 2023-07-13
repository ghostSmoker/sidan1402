# Generated by Django 4.1.7 on 2023-06-10 05:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0016_alter_user_first_name_alter_user_last_name'),
    ]

    operations = [
        migrations.AlterField(
            model_name='bill',
            name='inp',
            field=models.PositiveIntegerField(blank=True, default='', null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='ins',
            field=models.PositiveIntegerField(blank=True, default='', null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='inty',
            field=models.PositiveIntegerField(blank=True, default='', null=True),
        ),
        migrations.AlterField(
            model_name='user',
            name='national_code',
            field=models.BigIntegerField(null=True, unique=True),
        ),
    ]