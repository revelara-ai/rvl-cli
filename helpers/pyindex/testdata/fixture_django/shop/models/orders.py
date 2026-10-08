from django.db import models


class TimeStamped(models.Model):
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        abstract = True


class Order(TimeStamped):
    total = models.IntegerField()
