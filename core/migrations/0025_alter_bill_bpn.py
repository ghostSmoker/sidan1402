# Generated by Django 4.1.7 on 2023-06-19 12:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0024_alter_bill_inp_alter_bill_ins'),
    ]

    operations = [
        migrations.AlterField(
            model_name='bill',
            name='bpn',
            field=models.CharField(blank=True, default='a12345678', max_length=255, null=True),
        ),
    ]
