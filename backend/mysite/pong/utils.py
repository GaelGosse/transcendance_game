import pyotp
from datetime import datetime, timedelta
from .models import NewUser, Tournament, Party, Chat, Message, Statistic, Participant, Friendship, BlockedUser
from django import forms

#class CustomPasswordChangeForm(PasswordChangeForm):
#    old_password = forms.CharField(widget=forms.PasswordInput, label="Old Password")
#    new_password1 = forms.CharField(widget=forms.PasswordInput, label="New Password")
#    new_password2 = forms.CharField(widget=forms.PasswordInput, label="Confirm New Password")

#    class Meta:
#        model = User
#        fields = ('old_password', 'new_password1', 'new_password2')

def get_friends(user):
    # Get friends where the user is either person1 or person2
    friends_from_person1 = Friendship.objects.filter(person1=user).values_list('person2', flat=True)
    friends_from_person2 = Friendship.objects.filter(person2=user).values_list('person1', flat=True)

    # Combine both querysets and fetch user objects
    friend_ids = list(friends_from_person1) + list(friends_from_person2)
    friends = NewUser.objects.filter(id__in=friend_ids)
    return friends