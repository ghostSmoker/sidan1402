# Generated by Django 4.1.7 on 2023-06-20 21:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0029_alter_bill_inno_alter_bill_irtaxid_alter_bill_taxid'),
    ]

    operations = [
        migrations.AlterField(
            model_name='bill',
            name='inno',
            field=models.CharField(blank=True, default='00094238B6', max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='irtaxid',
            field=models.CharField(blank=True, default='A16G7G04C4800094238B64', max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='taxid',
            field=models.CharField(blank=True, default='A16G7G04C4800094238B64', max_length=255, null=True),
        ),
    ]
