# Generated by Django 4.0.4 on 2022-04-29 15:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('poll', '0012_block'),
    ]

    operations = [
        migrations.AlterField(
            model_name='block',
            name='id',
            field=models.IntegerField(default=0, primary_key=True, serialize=False),
        ),
    ]