from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.urls import reverse
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from base64 import b64encode
from django.core.files.base import ContentFile
from .utils import get_friends
from .models import NewUser, Tournament, Party, Chat, Message, Statistic, Participant, Friendship, BlockedUser
from django.http import HttpResponse, HttpResponseRedirect
from datetime import datetime, timedelta
from django.db.models import Q
import pyotp
import qrcode
from io import BytesIO
import base64



def index(request):
	if not request.user.is_authenticated:
		return HttpResponseRedirect(reverse("login"))
	return (render(request, "pong/homepage.html"))


def login_view(request):
	if not request.user.is_authenticated:
		return render(request,"pong/login.html")
	else:
		#ça serait bien de rajouter une notification "vous êtes déjà connecté"
		return HttpResponseRedirect(reverse("index"))

def signup(request):
	if request.user.is_authenticated:
		#ça serait bien de rajouter une notification "vous êtes déjà connecté"
		return HttpResponseRedirect(reverse("index"))
	if request.method == "POST":
		email = request.POST.get("email")
		password = request.POST.get("password")
		confirm_password = request.POST.get("confirm_password")
		avatar = request.FILES.get("avatar")
		pseudo = request.POST.get("pseudo")

		if (confirm_password.casefold() != password.casefold()) :
			return render(request, 'pong/signup.html', {
				'error_message': "Password don't match, please try again."
			})

		if NewUser.objects.filter(pseudo=pseudo).exists():
			return render(request, 'pong/signup.html', {
				'error_message': "Username already exists. Please choose a different pseudo."
			})


		if NewUser.objects.filter(email=email).exists():
			return render(request, 'pong/signup.html', {
				'error_message': "Email already exists. Please choose a different email."
			})


		user = NewUser.objects.create_user(email=email, password=password, pseudo=pseudo, avatar=avatar)
		user.save()
		print(user.id)
		return HttpResponseRedirect(reverse("index"))
	else:
		return render(request, "pong/signup.html")


def signin(request):
	if request.user.is_authenticated:
		#ça serait bien de rajouter une notification "vous êtes déjà connecté"
		return HttpResponseRedirect(reverse("index"))
	if request.method == "POST":
		email = request.POST.get("email")
		password = request.POST.get("password")
		user = authenticate(request, email=email, password=password)
		if user is not None:
			# login(request, user)
			request.session['user_id'] = user.id
			if user.is_mfa_enabled is True:
				#send_otp(request)
				#request.session["email"] = email
				return redirect("otp")
			else:
				login(request, user)
				return HttpResponseRedirect(reverse("index"))
		else:
			return render(request, "pong/signin.html", {
				"message": "Invalid credentials."
			})
	else:
		return render(request, "pong/signin.html")
#faire la ologique du otp sur la view otp avec la comparaison du code que le mec aura recu (comme il a deja scanné)
def otp_view(request):
	user = NewUser.objects.get(id=(request.session.get('user_id')))
	message = 'nothing'
	value = False
	if request.method == "POST":
		otp = request.POST["otp"]
		totp = pyotp.TOTP(user.mfa_hash) #check the secret key
		if totp.verify(otp): # the case where we can login the user
			login(request, user)
			return HttpResponseRedirect(reverse("index"))
		else: # le cas où la secret key n'est pas la bonne
			value = True
			message = 'invalid one time password or the password has expired'
	return render(request, 'pong/otp.html' , {
												'error_message' : {
																		'value' : value,
																		'message' : message
																}
											})

def statistics(request):
	if not request.user.is_authenticated:
		return HttpResponseRedirect(reverse("index"))
	user = request.user
	statistics = user.statistic
	return render(request, "pong/statistics.html", {'user' : user, 'statistics' : statistics})

def chat(request):
	return render(request, "pong/chat.html")

def logout_view(request):
	if request.user.is_authenticated:
		logout(request)
	return redirect('login')

def profile_view(request):
	if not request.user.is_authenticated:
		return HttpResponseRedirect(reverse("login"))
	user = NewUser.objects.get(id=(request.session.get('user_id')))
	url = pyotp.totp.TOTP(user.mfa_hash).provisioning_uri(name=user.email, issuer_name="Pong")
	qr = qrcode.make(url)
	buffered = BytesIO()
	qr.save(buffered)
	qr_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')

	if request.method == "POST":
		choice = request.POST.get("options")
		if choice == "enabled":
			user.is_mfa_enabled = True
			user.save()
		else:
			user.is_mfa_enabled = False
			user.save()
	try:
		user_avatar = user.avatar.url
	except ValueError:
		user_avatar = None

	friends = get_friends(user)

	return render(request, "pong/profile.html", {
														'user_info' : {
															'user_choice' : user.is_mfa_enabled,
															'user_url'    : qr_base64,
															'user_pseudo' : user.pseudo,
															'user_email' : user.email,
															'user_avatar' : user_avatar,
															'user_friends' : friends,
															'user_blocked_users': "test"

															}
													})



def add_friends(request):
	if not request.user.is_authenticated:
		return HttpResponseRedirect(reverse("login"))
	user = NewUser.objects.get(id=(request.session.get('user_id')))
	if request.method == "POST":
		friend_pseudo = request.POST.get("friend_pseudo")
		friend_user = None
		try:
			friend_user = NewUser.objects.get(pseudo=friend_pseudo)
		except NewUser.DoesNotExist:
			friend_user = None
		#empecher d'etre amis avec sois même
		if ( friend_user is not None) and (user.id is not friend_user.id) :
			# Check if they are already friends
			if Friendship.objects.filter(person1=user, person2=friend_user).exists() or Friendship.objects.filter(person1=friend_user, person2=user).exists():
				return render(request, "pong/add_friends.html", {
												'error_message' : {
																		'value' : True,
																		'message' : "you are already friends"
																}
											})

		# Create the friendship
			Friendship.objects.create(person1=user, person2=friend_user)
			return HttpResponseRedirect(reverse("profile"))
		else:
			if friend_user is None:
				message = "this user doesn't exist"
			else:
				message = "you can't add yourself as friend"
			return render(request, "pong/add_friends.html", {
												'error_message' : {
																		'value' : True,
																		'message' : message
																}
											})
	else:
		return render(request, "pong/add_friends.html", {
												'error_message' : {
																		'value' : False,
																		'message' : "nothing"
																}
											})




def delete_friends(request):
	if not request.user.is_authenticated:
		return HttpResponseRedirect(reverse("login"))
	user = NewUser.objects.get(id=(request.session.get('user_id')))
	if request.method == "POST":
		friend_pseudo = request.POST.get("friend_pseudo")
		friend_user = None
		try:
			friend_user = NewUser.objects.get(pseudo=friend_pseudo)
		except NewUser.DoesNotExist:
			friend_user = None

		if ( friend_user is not None) and (user.id is not friend_user.id) :
			friendship = Friendship.objects.filter(Q(person1=user, person2=friend_user) | Q(person1=friend_user, person2=user)).first()
			if friendship:
				friendship.delete()
			else:
				message = "you are not friends"
				return render(request, "pong/delete_friends.html", {
												'error_message' : {
																		'value' : True,
																		'message' : message
																}
												})
			return HttpResponseRedirect(reverse("profile")) #succes delete frfiend
		else:
			if friend_user is None:
				message = "this user doesn't exist"
			else:
				message = "you can't delete yourself as friend"
			return render(request, "pong/delete_friends.html", {
												'error_message' : {
																		'value' : True,
																		'message' : message
																}
											})
	else:
		return render(request, "pong/delete_friends.html", {
												'error_message' : {
																		'value' : False,
																		'message' : "nothing"
																}
											})


def waiting_room(request):
	if not request.user.is_authenticated:
		return HttpResponseRedirect(reverse("login"))
	user = request.user
	other_user = NewUser.objects.filter(in_waiting_room=True).exclude(id=user.id).first()
	if other_user:
		print(" - ")
		print(" @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ ")
		print(other_user.pseudo)
		print(" - ")
		party = Party.objects.create(user1=user, user2=other_user, game_name='Game Name', game_time=timedelta(minutes=30))
		user.in_waiting_room = False
		other_user.in_waiting_room = False
		user.save()
		other_user.save()
		return render(request, 'waiting_room.html')
	else:
		user.in_waiting_room = True
		user.save()
		print(" ")
		print(" else wait ")
		print(" ")
		return render(request, 'waiting_room.html')

def check_match(request):
	if not request.user.is_authenticated:
		return HttpResponseRedirect(reverse("login"))

	user = request.user
	party = Party.objects.filter(Q(user1=user) | Q(user2=user), is_ended=False).last()
	if party and party.user1 and party.user2:
		print(" ")
		print("found OK !")
		print(" ")
		# party.user1.in_waiting_room = False
		# party.user2.in_waiting_room = False
		# party.user1.save()
		# party.user2.save()
		return JsonResponse({
			'match_found': True,
			'party_id': party.id,
			'check_match': True,
			'red_user': party.user1.pseudo,
			'blue_user': party.user2.pseudo
		})
	else:
		print(" ")
		print("Nothing")
		print(" ")
		return JsonResponse({
			'match_found': False})

def game_page(request, party_id):
	if not request.user.is_authenticated:
		return HttpResponseRedirect(reverse("login"))

	party = get_object_or_404(Party, id=party_id)
	# user
	print(party)
	return render(request, 'game_page.html', {'party': party})

def home_game(request):
	if not request.user.is_authenticated:
		return HttpResponseRedirect(reverse("login"))

	return render(request, 'home_game.html')