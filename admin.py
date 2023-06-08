from django.contrib import admin
from .models import Msgs, Chat, Invite, User, AccountAuth, TempTimeout

# Register your models here.

class MsgsAdmin(admin.ModelAdmin):
    list_display = ['cid','json', 'time', 'date']
admin.site.register(Msgs, MsgsAdmin)

class ChatAdmin(admin.ModelAdmin):
    list_display = ['cid', 'users']
admin.site.register(Chat, ChatAdmin)

class UserAdmin(admin.ModelAdmin):
    list_display = ['uid', 'chats', 'time', 'date']
admin.site.register(User, UserAdmin)

class InviteAdmin(admin.ModelAdmin):
    list_display = ['cid', 'msg', 'time', 'date']
admin.site.register(Invite, InviteAdmin)

class AccountAuthAdmin(admin.ModelAdmin):
    list_display = ['uid', 'publishing_date']
admin.site.register(AccountAuth, AccountAuthAdmin)

class TempTimeoutAdmin(admin.ModelAdmin):
    list_display = ['num']
admin.site.register(TempTimeout, TempTimeoutAdmin)
