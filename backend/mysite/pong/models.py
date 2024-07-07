from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, UserManager, BaseUserManager
from django.core.exceptions import ValidationError
import imghdr
import pyotp

def validate_image(data):
	"""
	Validate that the uploaded data is a valid image.
	"""
	image_format = imghdr.what(None, h=data)
	if not image_format:
		raise ValidationError('Invalid image format.')

class CustomAccountManager(BaseUserManager):
	def create_superuser(self, email, pseudo, password, **other_fields):
		other_fields.setdefault('is_staff', True)
		other_fields.setdefault('is_superuser', True)

		#if other_fields.get('is_staff') is not True:
		#	raise ValueError('Superuser must have is_staff=True.')
		#if other_fields.get('is_superuser') is not True:
		#	raise ValueError('Superuser must have is_superuser=True.')
		return self.create_user(email, pseudo, password, **other_fields)

	def create_user(self, email, pseudo, password, **other_fields):

		email = self.normalize_email(email)
		user = self.model(email=email, pseudo=pseudo, **other_fields)
		user.set_password(password)
		user.mfa_hash = pyotp.random_base32()
		user.save(using=self._db)
		return user

class NewUser(AbstractBaseUser, PermissionsMixin):
	pseudo = models.CharField(max_length=20, unique=True)
	email = models.EmailField(unique=True)
	avatar = models.ImageField(upload_to='avatars/', validators=[validate_image], null=True, blank=True)
	friends = models.ManyToManyField('self', through='Friendship')
	created_at = models.DateTimeField(auto_now_add=True)
	statistic = models.OneToOneField('Statistic', on_delete=models.CASCADE, null=True, blank=True, related_name='user_statistic')
	blocked_users = models.ManyToManyField('self', through='BlockedUser', symmetrical=False, related_name='blocking_users', blank=True)
	is_active = models.BooleanField(default=True)
	is_staff = models.BooleanField(default=False)
	mfa_hash = models.CharField(max_length = 50, null=True, blank=True)
	is_mfa_enabled = models.BooleanField(default=False)
	objects = CustomAccountManager()
	in_waiting_room = models.BooleanField(default=False)


	groups = models.ManyToManyField(
		'auth.Group',
		related_name='pong_user_set',  # Ajout de related_name unique
		blank=True,
		help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.',
		related_query_name='pong_user',
	)
	user_permissions = models.ManyToManyField(
		'auth.Permission',
		related_name='pong_user_set',  # Ajout de related_name unique
		blank=True,
		help_text='Specific permissions for this user.',
		related_query_name='pong_user',
	)

	USERNAME_FIELD = 'email'
	REQUIRED_FIELDS = ['pseudo']

	def __str__(self):
		return self.pseudo

	def block_user(self, user):
		self.blocked_users.add(user)

	def unblock_user(self, user):
		self.blocked_users.remove(user)

	def is_blocked(self, user):
		return self.blocked_users.filter(id=user.id).exists()

class BlockedUser(models.Model):
	blocked_user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='blocked_by_users', on_delete=models.CASCADE)
	blocker = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='blocked_users_set', on_delete=models.CASCADE)

	class Meta:
		constraints = [
			models.UniqueConstraint(fields=['blocked_user', 'blocker'], name='unique_blocked_user')
		]

	def __str__(self):
		return f"{self.blocker.pseudo} blocked {self.blocked_user.pseudo}"


class Chat(models.Model):
    name = models.CharField(max_length=255)
    participants = models.ManyToManyField(settings.AUTH_USER_MODEL, through='Participant', related_name='chats')
    messages = models.ManyToManyField('Message', related_name='chats', blank=True)

    def __str__(self):
        return self.name

class Participant(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='participants')
    chat = models.ForeignKey('Chat', on_delete=models.CASCADE, related_name='chat_participants')
    joined_at = models.DateTimeField(auto_now_add=True)
    is_admin = models.BooleanField(default=False)

    def __str__(self):
        return f'{self.user.pseudo} in {self.chat.name} ({"Admin" if self.is_admin else "Member"})'

class Message(models.Model):
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='messages')
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.sender.pseudo}: {self.content}'

def send_message(chat, sender, content):
	message = Message.objects.create(sender=sender, content=content)
	chat.messages.add(message)

	# Deliver the message to participants who haven't blocked the sender
	for participant in chat.participants.all():
		if not participant.is_blocked(sender):
			# Logic to deliver the message to the participant
			pass

class Friendship(models.Model):
	person1 = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='friendships', on_delete=models.CASCADE)
	person2 = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='friends_of', on_delete=models.CASCADE)
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		constraints = [
			models.UniqueConstraint(fields=['person1', 'person2'], name='unique_friendship')
		]

	def __str__(self):
		return f"{self.person1.pseudo} is friends with {self.person2.pseudo}"

class Tournament(models.Model):
	name = models.CharField(max_length=100)
	winner = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='won_tournaments', on_delete=models.CASCADE)
	participant1 = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='participated_tournaments1', on_delete=models.CASCADE)
	participant2 = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='participated_tournaments2', on_delete=models.CASCADE)
	participant3 = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='participated_tournaments3', on_delete=models.CASCADE)
	participant4 = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='participated_tournaments4', on_delete=models.CASCADE)

	def __str__(self):
		return f"Tournament name is {self.name} - winner is {self.winner}"

class Party(models.Model):
	game_name = models.CharField(max_length=100)
	game_time = models.DurationField(default=0)
	date = models.DateTimeField(auto_now_add=True)
	user1 = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='user1', on_delete=models.CASCADE, default=1)
	user2 = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='user2', on_delete=models.CASCADE, default=1)
	score1 = models.IntegerField(default=0)
	score2 = models.IntegerField(default=0)
	is_ended = models.BooleanField(default=False)
	tournament = models.ForeignKey(Tournament, related_name='parties', on_delete=models.SET_NULL, null=True, blank=True)

	def __str__(self):
		tournament_name = self.tournament.name if self.tournament else 'No tournament'
		return f"Game name is {self.game_name} - {self.user1} vs {self.user2} did {self.score1}/{self.score2} on {self.date} at tournament {tournament_name}"

class Statistic(models.Model):
	user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='statistic_user')
	nbr_won_parties = models.IntegerField(default=0)
	nbr_lose_parties = models.IntegerField(default=0)
	total_time_played = models.DurationField(default=0)
	nbr_won_tournaments = models.IntegerField(default=0)

	def __str__(self):
		return f"Statistics for {self.user.pseudo} - won parties : {self.nbr_won_parties} - lose parties : {self.nbr_won_parties} - won tournament : {self.nbr_won_tournaments} - total time played : {self.total_time_played}"
