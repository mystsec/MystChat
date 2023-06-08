import jsonfield
import uuid
from django.db import models
import datetime
from django.utils import timezone

# Create your models here.

class Msgs(models.Model):
    cid = models.TextField()
    json = jsonfield.JSONField()
    time = models.TimeField(auto_now=False, auto_now_add=True)
    date = models.DateField(auto_now=False, auto_now_add=True)

class Chat(models.Model):
    cid = models.TextField()
    users = models.TextField()
    temp = models.BooleanField(default=False)

class User(models.Model):
    uid = models.TextField()
    chats = jsonfield.JSONField(default=dict)
    uk = models.TextField(editable=False)
    salt = models.TextField(editable=False)
    pbk = models.TextField(editable=False)
    spk = models.TextField(editable=False)
    sprk = models.TextField(editable=False)
    time = models.TimeField(auto_now=False, auto_now_add=True)
    date = models.DateField(auto_now=False, auto_now_add=True)

class Invite(models.Model):
    sender = models.TextField(editable=False)
    cid = models.TextField()
    uid = models.TextField(editable=False)
    key = models.TextField(editable=False)
    msg = models.TextField()
    time = models.TimeField(auto_now=False, auto_now_add=True)
    date = models.DateField(auto_now=False, auto_now_add=True)

class AccountAuth(models.Model):
    uid = models.TextField()
    uuid = models.TextField(editable=False)
    uid = models.TextField()
    time = models.TextField(editable=False)
    salt = models.TextField(editable=False)
    publishing_date = models.DateTimeField(default=timezone.now, blank=True)

    @property
    def delete_after_time(self):
        time = self.publishing_date + datetime.timedelta(minutes=60)
        if time < datetime.datetime.now():
            e = Event.objects.get(pk=self.pk)
            e.delete()
            return True
        else:
            return False

class TempAccess(models.Model):
    tid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, max_length=36)
    cid = models.TextField(editable=False)
    date = models.DateTimeField(default=timezone.now)

    @property
    def delete_7dys(self):
        time = self.date + datetime.timedelta(minutes=10080)
        if time.timestamp() < datetime.datetime.now().timestamp():
            tcid = self.cid
            TempAuth.objects.filter(cid=tcid).delete()
            Chat.objects.filter(cid=tcid).delete()
            Msgs.objects.filter(cid=tcid).delete()
            try:
                TempTimeout.objects.get(cid=tcid).delete()
            except:
                print('no timeout found')
            TempKey.objects.filter(cid=tcid).delete()
            TempAccess.objects.filter(pk=self.pk).delete()
            TempId.objects.filter(cid=tcid).delete()
            return True
        else:
            return False

class TempKey(models.Model):
    cid = models.TextField(editable=False)
    key = models.TextField(editable=False)
    iv = models.TextField(editable=False)

class TempAuth(models.Model):
    cid = models.TextField(editable=False)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, max_length=36)

class TempId(models.Model):
    cid = models.TextField(editable=False)
    tid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, max_length=36)
    ad = models.BooleanField(default=False)

class TempTimeout(models.Model):
    num = models.UUIDField(default=uuid.uuid4, editable=False, max_length=36)
    date = models.DateTimeField(default=timezone.now)
    cid = models.TextField(editable=False)

    @property
    def delete_24hrs(self):
        time = self.date + datetime.timedelta(minutes=1440)
        if time.timestamp() < datetime.datetime.now().timestamp():
            tcid = self.cid
            TempAuth.objects.filter(cid=tcid).delete()
            Chat.objects.filter(cid=tcid).delete()
            Msgs.objects.filter(cid=tcid).delete()
            TempTimeout.objects.get(pk=self.pk).delete()
            TempKey.objects.filter(cid=tcid).delete()
            TempAccess.objects.filter(cid=tcid).delete()
            TempId.objects.filter(cid=tcid).delete()
            return True
        else:
            return False

