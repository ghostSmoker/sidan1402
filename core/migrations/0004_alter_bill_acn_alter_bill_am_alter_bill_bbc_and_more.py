# Generated by Django 4.1.7 on 2023-05-24 12:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0003_user_client_id_user_private_key'),
    ]

    operations = [
        migrations.AlterField(
            model_name='bill',
            name='acn',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='am',
            field=models.FloatField(null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='bbc',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='bid',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='billid',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='bpc',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='bsrn',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='crn',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='indati2m',
            field=models.BigIntegerField(max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='indatim',
            field=models.BigIntegerField(max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='mu',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='pcn',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='pdt',
            field=models.BigIntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='pid',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='sbc',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='scc',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='scln',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='sstid',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='tinb',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='tins',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='trmn',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='bill',
            name='trn',
            field=models.CharField(max_length=255, null=True),
        ),
    ]