from django.db import models

# Create your models here.
class psvtOnvifModels(models.Model):

    ip = models.CharField(max_length=20, blank=False, null=False)
    port = models.CharField(max_length=20, blank=False)
    password = models.CharField(max_length=100, blank=False)
    username = models.CharField(max_length=100, blank=False)

    def __str__(self):
	    return self.ip

    def save(self, *args, **kwargs):
	    super(psvtOnvifModels, self).save(*args, **kwargs)