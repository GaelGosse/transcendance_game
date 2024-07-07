from django.contrib import admin
from .models import NewUser, Tournament, Party, Chat, Message, Statistic, Participant, Friendship, BlockedUser

admin.site.register(NewUser)
admin.site.register(Tournament)
admin.site.register(Party)
admin.site.register(Chat)
admin.site.register(Message)
admin.site.register(Statistic)
admin.site.register(Participant)
admin.site.register(Friendship)
admin.site.register(BlockedUser)


# Register your models here.
