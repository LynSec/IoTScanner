# Generated by Django 5.0.4 on 2024-04-12 07:00

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='PortScanResult',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('target_ip', models.CharField(max_length=15)),
                ('port', models.IntegerField()),
                ('status', models.CharField(max_length=10)),
            ],
        ),
    ]
