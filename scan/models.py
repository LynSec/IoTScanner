from django.db import models

class PortScanResult(models.Model):
    target_ip = models.CharField(max_length=15)
    port = models.IntegerField()
    status = models.CharField(max_length=10)
