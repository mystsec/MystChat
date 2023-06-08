from django.core.management.base import BaseCommand
from myst.models import Chat, Msgs, TempTimeout, TempAccess
import csv
import datetime

class Command(BaseCommand):
    print('Starting')
    def handle(self, *args, **options):
        temps = TempTimeout.objects.all()
        links = TempAccess.objects.all()
        msgs = Msgs.objects.all()
        print('Current:')
        for temp in temps:
            res = temp.delete_24hrs
            if res == True:
                self.stdout.write(self.style.SUCCESS('Purged'))
            elif res == False:
                self.stdout.write(self.style.SUCCESS('Passed'))
        print('Links:')
        for link in links:
            res = link.delete_7dys
            if res == True:
                self.stdout.write(self.style.SUCCESS('Purged'))
            elif res == False:
                self.stdout.write(self.style.SUCCESS('Passed'))
        print('Purges:')
        for msg in msgs:
            if Chat.objects.filter(cid=getattr(msg, 'cid')).exists():
                self.stdout.write(self.style.SUCCESS('Passed'))
            else:
                msg.delete()
                self.stdout.write(self.style.SUCCESS('Purged'))
        print('Ending')
