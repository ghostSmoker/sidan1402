# Generated by Django 4.1.7 on 2023-06-12 05:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0022_alter_bill_odt'),
    ]

    operations = [
        migrations.AlterField(
            model_name='bill',
            name='inp',
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='ins',
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
    ]