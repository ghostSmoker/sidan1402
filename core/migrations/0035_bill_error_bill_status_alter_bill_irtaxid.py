# Generated by Django 4.1.7 on 2023-07-06 07:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0034_bill_inno_bill_irtaxid_bill_taxid'),
    ]

    operations = [
        migrations.AddField(
            model_name='bill',
            name='error',
            field=models.CharField(max_length=2555, null=True),
        ),
        migrations.AddField(
            model_name='bill',
            name='status',
            field=models.CharField(max_length=25, null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='irtaxid',
            field=models.CharField(blank=True, default='A16G7G04C4800094238B64', max_length=255, null=True),
        ),
    ]
