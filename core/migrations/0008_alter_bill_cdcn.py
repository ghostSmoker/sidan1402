# Generated by Django 4.1.7 on 2023-05-24 12:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0007_bill_cdcn'),
    ]

    operations = [
        migrations.AlterField(
            model_name='bill',
            name='cdcn',
            field=models.CharField(max_length=255, null=True),
        ),
    ]
