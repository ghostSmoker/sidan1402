# Generated by Django 4.1.7 on 2023-05-24 12:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0004_alter_bill_acn_alter_bill_am_alter_bill_bbc_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='bill',
            name='indati2m',
            field=models.BigIntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='indatim',
            field=models.BigIntegerField(null=True),
        ),
    ]
