# Generated by Django 4.1.7 on 2023-07-08 16:20

import django.contrib.postgres.fields
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0035_bill_error_bill_status_alter_bill_irtaxid'),
    ]

    operations = [
        migrations.AlterField(
            model_name='bill',
            name='error',
            field=django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=2555, null=True), size=None),
        ),
    ]
