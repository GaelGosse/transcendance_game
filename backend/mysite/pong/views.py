from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.urls import reverse
from django.http import HttpResponse, HttpResponseRedirect
from base64 import b64encode
from django.utils import timezone
from django.core.files.base import ContentFile
from .utils import get_friends #, CustomPasswordChangeForm
from .models import NewUser, Tournament, Party, Chat, Message, Statistic, Participant, Friendship, BlockedUser
from datetime import datetime
from django.db.models import Q, F
from django.db import IntegrityError
from django import forms
import pyotp
import qrcode
from io import BytesIO
import base64
import sys
import json
from django.http import JsonResponse
from datetime import timedelta
from django.contrib import messages
from django.template.loader import render_to_string
from django.core.exceptions import ObjectDoesNotExist
import logging
import re
from django.db.models import Count


logger = logging.getLogger('pong')

# def index(request):
	# if not request.user.is_authenticated:
	#     return HttpResponseRedirect(reverse("login"))
	# return (render(request, "pong/homepage.html"))

def index(request) :
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {}, request=request)
			return (JsonResponse({'html' : html,
								'url' :   reverse("login")
				}))
			return JsonResponse({'redirect' : reverse("login")})
		else :
			return HttpResponseRedirect(reverse("login"))
	if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
		html = render_to_string("pong/homepage_content.html", {}, request=request)
		return (JsonResponse({'html' : html,
							'url' :   reverse("index")
				}))
	else :
		return render(request, "pong/homepage.html")

# def login_view(request):
	# if not request.user.is_authenticated:
	#     return render(request,"pong/login.html")
	# else:
	#     #ça serait bien de rajouter une notification "vous êtes déjà connecté"
	#     return HttpResponseRedirect(reverse("index"))

def login_view(request):
	if request.user.is_authenticated:
		message = "Vous êtes déjà connecté"
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/homepage_content.html", {'message': message}, request)
			return (JsonResponse({'html' : html,
							'url' :   reverse("index")
				}))
		else:
			# Vous pouvez ajouter un message flash pour afficher la notification sur la page d'accueil.
			#messages.add_message(request, messages.INFO, message)
			return HttpResponseRedirect(reverse("index"))
	else:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {}, request)
			return JsonResponse({'html': html,
								'url' : reverse("login")
								})
		else:
			return render(request, "pong/login.html")



# def signup(request):
	# if request.user.is_authenticated:
	#     message = "Vous êtes déjà connecté"
	#     # if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	#     #     return JsonResponse({'redirect': reverse("index"), 'message': message})
	#     # else:
	#         # Vous pouvez ajouter un message flash pour afficher la notification sur la page d'accueil.
	#     messages.add_message(request, messages.INFO, message)
	#     return HttpResponseRedirect(reverse("index"))
	# if request.method == "POST":
	#     email = request.POST.get("email")
	#     password = request.POST.get("password")
	#     confirm_password = request.POST.get("confirm_password")
	#     avatar = request.FILES.get("avatar")
	#     pseudo = request.POST.get("pseudo")

	#     if (confirm_password.casefold() != password.casefold()) :
	#         return render(request, 'pong/signup.html', {
	#             'error_message': "Password don't match, please try again."
	#         })

	#     if NewUser.objects.filter(pseudo=pseudo).exists():
	#         return render(request, 'pong/signup.html', {
	#             'error_message': "Username already exists. Please choose a different pseudo."
	#         })


	#     if NewUser.objects.filter(email=email).exists():
	#         return render(request, 'pong/signup.html', {
	#             'error_message': "Email already exists. Please choose a different email."
	#         })


	#     user = NewUser.objects.create_user(email=email, password=password, pseudo=pseudo, avatar=avatar)
	#     user.save()
	#     print(user.id)
	#     return HttpResponseRedirect(reverse("index"))
	# else:
	#     return render(request, "pong/signup.html")


def parsing_email(email) :
	if email :
		email = email.strip()
		try :
			index = email.index("@")
		except ValueError :
			logger.info("On passe ici exception")
			return ('')
		if ' ' in email :
			return ' '
		logger.info("oui oui")
		email_part = email[:index]
		domain_part = email[index+1:]
		logger.debug("email_part = %s", email_part)
		logger.debug("domain_part = %s", domain_part)
		if not email_part or '..' in email_part:
			return ''
		if not domain_part or '..' in domain_part:
			return ''
		if not (domain_part.endswith("com") or domain_part.endswith(".fr")) :
			return ('')
		email_invalid_chars = re.compile(r'[ !#\$%&\'\*\+\-/=\?\^_`\{\|\}~]')
		domain_invalid_chars = re.compile(r'[ !#\$%&\'\*\+\-/=\?\^_`\{\|\}~]')
		if email_invalid_chars.search(email_part) or domain_invalid_chars.search(domain_part):
			logger.info("Wrong char found !")
			return ''
	return (email)

def test_mail() :
	test_emails = [
		"example@'example.com",
		"example@example.fr",
		"example@ example.com",
		"example@example.c",
		"example@example.",
		" example@example.com ",
		"example@example..com",
		"example@example!.com"
	]

	for i,email in enumerate(test_emails):
		result = parsing_email(email)
		logger.debug("test n*%d retour fonction parsing = %s", i, result)


def validate_signup_data(email, password, confirm_password, pseudo):
	if not email :
		return "Email: this field can not be empty"
	if not password :
		return "Password: this field can not be empty"
	if not confirm_password :
		return "Confirm_password: this field can't be empty"
	if not pseudo:
		return "Pseudo: this field can't be empty"
	if confirm_password.casefold() != password.casefold():
		return "Password don't match, please try again."
	if NewUser.objects.filter(pseudo=pseudo).exists():
		return "Username already exists. Please choose a different pseudo."
	if NewUser.objects.filter(email=email).exists():
		return "Email already exists. Please choose a different email."
	return None


def signup(request):
	if request.user.is_authenticated:
		message = "Vous êtes déjà connecté"
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/homepage_content.html", {'message': message}, request=request)
			return JsonResponse({'html': html,
								'url' : reverse("index")
								})
		else:
			#messages.add_message(request, messages.INFO, message)
			return HttpResponseRedirect(reverse("index"))

	if request.method == "POST":
		print("Nous passons bien ici oui")
		email = request.POST.get("email")
		password = request.POST.get("password")
		confirm_password = request.POST.get("confirm_password")
		avatar = request.FILES.get("avatar")
		pseudo = request.POST.get("pseudo")

		logger.debug("email avant parsing = %s", email)

		email = parsing_email(email)

		# test_mail()

		logger.debug("email apres parsing = %s", email)
		logger.debug("pseudo = %s", pseudo)
		logger.debug("password = %s", password)
		logger.debug("confirm_password = %s", confirm_password)


		error_message = validate_signup_data(email, password, confirm_password, pseudo)

		# logger.debug("error_message = %s", error_message)

		if error_message:
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
				html = render_to_string("pong/signup_content.html", {'error_message': error_message}, request=request)
				return JsonResponse({'html': html,
									'url' : reverse("signup")
				})
			else:
				return render(request, 'pong/signup.html', {'error_message': error_message})

		user = NewUser.objects.create_user(email=email, password=password, pseudo=pseudo, avatar=avatar)
		# user.create_statistic()
		user.save()

		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {}, request=request)
			return JsonResponse({'html': html,
								'url' : reverse("index")
			})
		else:
			return HttpResponseRedirect(reverse("index"))

	else:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			print("Nous passons bien ici 2")
			logger.info("html at ajax")
			html = render_to_string("pong/signup_content.html", {}, request=request)
			logger.debug("html in signup = %s", html)
			return JsonResponse({'html': html,
								'url' : reverse("signup")
			})
		else:
			return render(request, "pong/signup.html")



# def signin(request):
	# if request.user.is_authenticated:
	#     #ça serait bien de rajouter une notification "vous êtes déjà connecté"
	#     return HttpResponseRedirect(reverse("index"))
	# if request.method == "POST":
	#     email = request.POST.get("email")
	#     password = request.POST.get("password")
	#     user = authenticate(request, email=email, password=password)
	#     alerte = False
	#     if user is not None:
	#         # login(request, user)
	#         request.session['user_id'] = user.id
	#         if user.is_mfa_enabled is True:
	#             #send_otp(request)
	#             #request.session["email"] = email
	#             return redirect("otp")
	#         else:
	#             login(request, user)
	#             return HttpResponseRedirect(reverse("index"))
	#     else:
	#         alerte = True
	#         return render(request, "pong/signin.html", {
	#             "error_message" : alerte,
	#             "message": "Invalid credentials."
	#         })
	# else:
	#     return render(request, "pong/signin.html")


def handle_authentication(request, email, password):
	user = authenticate(request, email=email, password=password)
	print("email =", email, "password =", password)
	if user is not None:
		request.session['user_id'] = user.id
		if user.is_mfa_enabled:
			return {'redirect': "pong/otp_content.html",
					'url' : reverse("otp")
			}
		else:
			login(request, user)
			return {'redirect': "pong/homepage_content.html",
					'url' : reverse("index")
			}
	else:
		return {'error_message': "Invalid credentials."}

def signin(request):
	if request.user.is_authenticated:
		message = "Vous êtes déjà connecté"
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/homepage_content.html", {'message': message}, request=request)
			return JsonResponse({'html': html,
								'url' : reverse("index")
			})
		else:
			#messages.add_message(request, messages.INFO, message)
			return HttpResponseRedirect(reverse("index"))

	if request.method == "POST":
		print("Je passe ici quand j'appuie sur LOGIN oui")
		email = request.POST.get("email")
		password = request.POST.get("password")

		result = handle_authentication(request, email, password)

		if 'error_message' in result:
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
				html = render_to_string("pong/signin_content.html", {'error_message': True, 'message': result['error_message']}, request=request)
				return JsonResponse({'html': html,
									'url' : reverse("signin")
				})
			else:
				return render(request, "pong/signin.html", {"error_message": True, "message": result['error_message']})
		else:
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
				html = render_to_string(result['redirect'], {}, request=request)
				return JsonResponse({'html': html,
									'url' : result['url']
				})
			else:
				new_url = result['redirect']
				new_url = new_url.replace("_content", "")
				return HttpResponseRedirect(new_url)

	else:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/signin_content.html", {}, request=request)
			logger.debug("html in sigin = %s", html)
			return JsonResponse({'html': html,
								'url': reverse("signin")
			})
		else:
			return render(request, "pong/signin.html")

#faire la ologique du otp sur la view otp avec la comparaison du code que le mec aura recu (comme il a deja scanné)
# def otp_view(request):
#     user = NewUser.objects.get(id=(request.session.get('user_id')))
#     message = 'nothing'
#     value = False
#     if request.method == "POST":
#         otp = request.POST["otp"]
#         totp = pyotp.TOTP(user.mfa_hash) #check the secret key
#         if totp.verify(otp): # the case where we can login the user
#             login(request, user)
#             return HttpResponseRedirect(reverse("index"))
#         else: # le cas où la secret key n'est pas la bonne
#             value = True
#             message = 'invalid one time password or the password has expired'
#     return render(request, 'pong/otp.html' , {
#                                                 'error_message' : {
#                                                                         'value' : value,
#                                                                         'message' : message
#                                                                 }
#                                             })

def otp_view(request):
	user = NewUser.objects.get(id=(request.session.get('user_id')))
	message = 'nothing'
	value = False
	if request.method == "POST":
		otp = ''.join([request.POST.get(f'otp_{i}') for i in range(6)])  # Récupère chaque chiffre du OTP
		totp = pyotp.TOTP(user.mfa_hash)  # Initialise TOTP avec le hachage MFA de l'utilisateur
		if totp.verify(otp):  # Vérifie si le OTP est correct
			login(request, user)  # Connecte l'utilisateur
			#return HttpResponseRedirect(reverse("index"))  # Redirige vers la page d'accueil
			html = render_to_string("pong/homepage_content.html", {}, request=request)
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
				return JsonResponse({'html': html,
								'url' : reverse("index")
				})
			else :
				return render(request, 'pong/otp.html' , {
												'error_message' : {
																		'value' : value,
																		'message' : message
																}
											})
		else:
			value = True
			message = 'invalid one time password or the password has expired'
			html = render_to_string("pong/otp_content.html", {'error_message': {
					'value': value,
					'message': message
				}}, request=request)
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
				return JsonResponse({'html': html,
								'url' : reverse('otp')
					})
			else :
				return render(request, 'pong/otp.html' , {
												'error_message' : {
																		'value' : value,
																		'message' : message
																}
											})

	return render(request, "pong/otp.html")

# def statistics(request):
	# if not request.user.is_authenticated:
	#     return HttpResponseRedirect(reverse("index"))
	# user = NewUser.objects.get(id=(request.session.get('user_id')))
	# statistics = user.statistic
	# history = []
	# partie = Party.objects.all()
	# for game in partie :
	#     winner = game.winner.pseudo.strip()
	#     loser = game.loser.pseudo.strip()
	#     if ((user.pseudo == winner) or (user.pseudo == loser)) :
	#         history.append(game)
	# game_date = []
	# game_result = []
	# game_result_numeric = []
	# for game in history :
	#     game_date.append(game.date.strftime('%Y-%m-%d'))
	#     if (game.winner.pseudo == user.pseudo) :
	#         game_result.append('Victory')
	#     elif (game.loser.pseudo == user.pseudo) :
	#         game_result.append('Defeat')
	# for result in game_result :
	#     if (result == "Victory") :
	#         game_result_numeric.append(1)
	#     else :
	#         game_result_numeric.append(-1)
	# nbr_day = 1
	# for i in range(1, len(game_date)):
	#     if game_date[i] != game_date[i - 1]:
	#         nbr_day += 1
	# data = {}
	# game_duration = timedelta()
	# for i in range(len(history)):
	#     game_duration += history[i].game_time
	#     if ((i == len(history) - 1) or (history[i].date.strftime('%Y-%m-%d') != history[i + 1].date.strftime('%Y-%m-%d'))) :
	#         data[history[i].date.strftime('%Y-%m-%d')] = game_duration.total_seconds()
	#         game_duration = timedelta()
	# return render(request, "pong/statistics.html", {
	#                                                 'user' : user,
	#                                                 'statistics' : statistics,
	#                                                 'history' : history,
	#                                                 'game_dates_json': json.dumps(game_date),
	#                                                 'game_results_json': json.dumps(game_result_numeric),
	#                                                 'game_duration_json' : json.dumps(data)
	#                                                 })

def statistics(request):
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {'message': message}, request=request)
			return JsonResponse({'html': html,
								'url' : reverse("index")
			})
		else:
			return HttpResponseRedirect(reverse("index"))
	user = NewUser.objects.get(id=(request.session.get('user_id')))
	if not user.statistic :
		logger.info("On passe la ouai")
		user_statistic, created = Statistic.objects.get_or_create(user=user)
		# user_statistic.nbr_won_parties += 1
	logger.debug("user = %s", user)
	logger.debug("statistics = %s", user_statistic)
	history = []
	partie = Party.objects.all()
	user_here = 0
	for game in partie :
		winner = game.winner.pseudo.strip()
		loser = game.loser.pseudo.strip()
		if ((user.pseudo == winner) or (user.pseudo == loser)) :
			history.append(game)
			user_here += 1
			user.nbr_parties = user_here
			logger.info("C'est ici que ca se passe")
			if user_statistic :
				if user.nbr_parties > (user_statistic.nbr_won_parties + user_statistic.nbr_lose_parties) :
					if user.pseudo == winner :
						logger.info("C'est ici que ca se passe")
						logger.debug(" nbr victoires avant = %d", user_statistic.nbr_won_parties)
						user_statistic.nbr_won_parties += 1
						logger.debug(" nbr victoires apres = %d", user_statistic.nbr_won_parties)
					else :
						user_statistic.nbr_lose_parties += 1
					if game.tournament and game.tournament.name :
						user_statistic.nbr_won_tournaments += 1
					user_statistic.save()
		# if user.pseudo == winner:
		# 	if user.statistic:
		# 		user.statistic.nbr_won_parties += 1
		# 	# else:
		# 	# 	# Vous pouvez créer l'objet Statistic ici si nécessaire
		# 	# 	logger.info("on passe dans le else")
		# 	# 	# user_statistic = Statistic.objects.create(user=user)
		# 	# 	user_statistic.nbr_lose_parties += 1
		# 	# 	user_statistic.save()
		# elif user.pseudo == loser :


	# logger.debug("user_here = %d", user_here)
	logger.debug("user stats = %s", user_statistic)
	game_date = []
	game_result = []
	game_result_numeric = []
	for game in history :
		game_date.append(game.date.strftime('%Y-%m-%d'))
		if (game.winner.pseudo == user.pseudo) :
			game_result.append('Victory')
		elif (game.loser.pseudo == user.pseudo) :
			game_result.append('Defeat')
	for result in game_result :
		if (result == "Victory") :
			game_result_numeric.append(1)
		else :
			game_result_numeric.append(-1)
	nbr_day = 1
	for i in range(1, len(game_date)):
		if game_date[i] != game_date[i - 1]:
			nbr_day += 1
	data = {}
	game_duration = timedelta()
	for i in range(len(history)):
		game_duration += history[i].game_time
		if user_statistic :
			user_statistic.total_time_played += history[i].game_time
		if ((i == len(history) - 1) or (history[i].date.strftime('%Y-%m-%d') != history[i + 1].date.strftime('%Y-%m-%d'))) :
			data[history[i].date.strftime('%Y-%m-%d')] = game_duration.total_seconds()
			game_duration = timedelta()
	if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/statistics_content.html", {'user' : user,
																	'statistics' : user_statistic,
																	'history' : history,
																	'game_dates_json': json.dumps(game_date),
																	'game_results_json': json.dumps(game_result_numeric),
																	'game_duration_json' : json.dumps(data),
																	'css_file' : 'pong/css/statistics.css',
																	}, request=request)
			return JsonResponse({'html': html,
								'url' : reverse("statistics")
			})
	else :
		return render(request, "pong/statistics.html", {
													'user' : user,
													'statistics' : user_statistic,
													'history' : history,
													'game_dates_json': json.dumps(game_date),
													'game_results_json': json.dumps(game_result_numeric),
													'game_duration_json' : json.dumps(data),
													'css_file' : 'pong/css/statistics.css',
													})


def chat(request):
	return render(request, "pong/chat.html")

# def logout_view(request):
	# if request.user.is_authenticated:
	#     logout(request)
	# return redirect('login')


# def logout_view(request):
	# if request.user.is_authenticated:
	#     logout(request)

	# if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	#     html = render_to_string("pong/login_content.html", {}, request=request)
	#     return JsonResponse({'html': html})
	# else:
	#     return HttpResponseRedirect(reverse('login'))

def logout_view(request):
	if request.user.is_authenticated:
		user = NewUser.objects.get(id=(request.session.get('user_id')))
		user.is_active = False
		user.save()
		logout(request)

	if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
		html = render_to_string("pong/login_content.html", {}, request=request)
		return JsonResponse({'html': html})
	else:
		return HttpResponseRedirect(reverse('login'))


def profile_view(request):
	#gérer block user
	#gérer cliquer sur un user et redirigé vers profil plus simple
	#faire spa
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {}, request)
			return JsonResponse({'html': html,
								'url' : reverse("login")
								})
		else:
			return HttpResponseRedirect(reverse("login"))

	user = NewUser.objects.get(id=(request.session.get('user_id')))
	url = pyotp.totp.TOTP(user.mfa_hash).provisioning_uri(name=user.email, issuer_name="Pong")
	qr = qrcode.make(url)
	buffered = BytesIO()
	qr.save(buffered)
	qr_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
	try:
		user_avatar = user.avatar.url
	except ValueError:
		user_avatar = None
	friends = get_friends(user)
	password_form_errors = []
	other_error  = {
		"avatar" : None,
		"email" : None,
		"pseudo" : None
	}


	if request.method == "POST":
		if request.POST.get("options"):
			choice = request.POST.get("options")
			if choice == "enabled":
				user.is_mfa_enabled = True
				user.save()
			else:
				user.is_mfa_enabled = False
				user.save()
			#return HttpResponseRedirect(reverse("profile"))
		if request.POST.get("change_pseudo"):
			if user.pseudo is not request.POST.get("change_pseudo"):
				try:
					test = NewUser.objects.get(pseudo=request.POST.get("change_pseudo"))
					other_error["pseudo"] = "this pseudo already exist"
				except NewUser.DoesNotExist:
					user.pseudo = request.POST.get("change_pseudo")
					user.save()
			else:
				other_error["pseudo"] = "you are already name like this"

		if request.FILES.get("change_avatar"):
			user.avatar = request.FILES.get("change_avatar")
			user.save()
			user_avatar = user.avatar.url
			update_session_auth_hash(request, user)
		if request.POST.get("change_email"):
			if user.email is not request.POST.get("change_email"):
				try:
					test = NewUser.objects.get(email=request.POST.get("change_email"))
					other_error["email"] =  "this email already exist"
				except NewUser.DoesNotExist:
					user.email = request.POST.get("change_email")
					user.save()
					update_session_auth_hash(request, user)
			else:
				other_error["email"] = "your email is already this one"

		if request.POST.get("old_password"):
			old_password = request.POST.get("old_password")
			new_password1 = request.POST.get("new_password1")
			new_password2 = request.POST.get("new_password2")

			if new_password1 and new_password2 and old_password:
				if new_password1 == new_password2:
					if user.check_password(old_password):
						user.set_password(new_password1)
						user.save()
						update_session_auth_hash(request, user)  # Important to update session
						return HttpResponseRedirect(reverse("index"))
					else:
						password_form_errors.append('Old password is incorrect.')
				else:
					password_form_errors.append('New passwords do not match.')
			else:
				password_form_errors.append('Please fill out all password fields.')
	if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
		html = render_to_string("pong/profile_content.html", {
														'user_info' : {
															'user_choice' : user.is_mfa_enabled,
															'user_url'    : qr_base64,
															'user_pseudo' : user.pseudo,
															'user_email' : user.email,
															'user_avatar' : user_avatar,
															'user_friends' : friends,
															'user_blocked_users': "test"

															},
															'password_form_errors': password_form_errors,
															'other_error': other_error}, request=request)
		return JsonResponse({'html': html,
								'url' : reverse("profile")
								})
	else:
		return render(request, "pong/profile.html", {
														'user_info' : {
															'user_choice' : user.is_mfa_enabled,
															'user_url'    : qr_base64,
															'user_pseudo' : user.pseudo,
															'user_email' : user.email,
															'user_avatar' : user_avatar,
															'user_friends' : friends,
															'user_blocked_users': "test"

															},
															'password_form_errors': password_form_errors,
															'other_error': other_error
													})



# def add_friends(request):
	# if not request.user.is_authenticated:
	#     if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	#         html = render_to_string("pong/login_content.html", {}, request=request)
	#         return JsonResponse({'html': html})
	#     else:
	#         return HttpResponseRedirect(reverse("login"))

	# user = NewUser.objects.get(id=(request.session.get('user_id')))

	# if request.method == "POST":
	#     friend_pseudo = request.POST.get("friend_pseudo")
	#     friend_user = None
	#     try:
	#         friend_user = NewUser.objects.get(pseudo=friend_pseudo)
	#     except NewUser.DoesNotExist:
	#         friend_user = None
	#     #empecher d'etre amis avec sois même
	#     if ( friend_user is not None) and (user.id is not friend_user.id) :
	#         # Check if they are already friends
	#         if Friendship.objects.filter(person1=user, person2=friend_user).exists() or Friendship.objects.filter(person1=friend_user, person2=user).exists():
	#             if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	#                 html = render_to_string("pong/add_friends_content.html", {'error_message' : {
	#                                                                     'value' : True,
	#                                                                     'message' : "you are already friends"
	#                                                             }
	#                                         }, request=request)
	#                 return JsonResponse({'html': html,
	#                             'url' : reverse("add_friends")
	#                 })
	#             else:
	#                 return render(request, "pong/add_friends.html", {
	#                                             'error_message' : {
	#                                                                     'value' : True,
	#                                                                     'message' : "you are already friends"
	#                                                             }
	#                                         })

	#     # Create the friendship
	#         Friendship.objects.create(person1=user, person2=friend_user)
	#         if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	#             html = render_to_string("pong/add_friends_content.html", {'error_message' : {
	#                                                                     'value' : True,
	#                                                                     'message' : "you are now friends"
	#                                                             }
	#                                         }, request=request)
	#             return JsonResponse({'html': html,
	#                             'url' : reverse("add_friends")
	#                 })
	#         else:
	#             return render(request, "pong/add_friends.html", {
	#                                             'error_message' : {
	#                                                                     'value' : True,
	#                                                                     'message' : "you are now friends"
	#                                                             }
	#                                         })

	#     else:
	#         if friend_user is None:
	#             message = "this user doesn't exist"
	#         else:
	#             message = "you can't add yourself as friend"
	#         if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	#                 html = render_to_string("pong/add_friends_content.html", {'error_message' : {
	#                                                                     'value' : True,
	#                                                                     'message' : message
	#                                                             }
	#                                         }, request=request)
	#                 return JsonResponse({'html': html,
	#                             'url' : reverse("add_friends")
	#                 })
	#         else:
	#             return render(request, "pong/add_friends.html", {
	#                                             'error_message' : {
	#                                                                     'value' : True,
	#                                                                     'message' : message
	#                                                             }
	#                                         })
	# else:
	#     if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	#                 html = render_to_string("pong/add_friends_content.html", {'error_message' : {
	#                                                                     'value' : False,
	#                                                                     'message' : "nothing"
	#                                                             }
	#                                         }, request=request)
	#                 return JsonResponse({'html': html,
	#                             'url' : reverse("add_friends")
	#                 })
	#     else:
	#         return render(request, "pong/add_friends.html", {
	#                                             'error_message' : {
	#                                                                     'value' : False,
	#                                                                     'message' : "nothing"
	#                                                             }
	#                                         })


def add_friends(request):
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {}, request=request)
			return JsonResponse({'html': html})
		else:
			return HttpResponseRedirect(reverse("login"))
	user = NewUser.objects.get(id=(request.session.get('user_id')))
	friend_user = get_friends(user)
	logger.debug("la liste des users amis : %s", friend_user)
	all_users = NewUser.objects.all()
	logger.debug("la liste des users  : %s", all_users)
	users_list = []
	for users in all_users :
		# logger.debug("amis = %s", users)
		if users not in friend_user and users != user and users.pseudo != "admin":
			users_list.append(users)
	logger.debug("la liste des users non amis : %s", users_list)
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
				if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
					html = render_to_string("pong/add_friends_content.html", {'error_message' : {
																		'value' : True,
																		'message' : "you are already friends"
																}, 'users_list' : users_list,
											}, request=request)
					return JsonResponse({'html': html,
								'url' : reverse("add_friends")
					})
				else:
					return render(request, "pong/add_friends.html", {
												'error_message' : {
																		'value' : True,
																		'message' : "you are already friends"
																}, 'users_list' : users_list,
											})

		# Create the friendship
			Friendship.objects.create(person1=user, person2=friend_user)
			logger.debug("friend_user = %s", friend_user)
			temp = friend_user.pseudo.upper()
			logger.debug("friend_user apres = %s", friend_user)
			message = temp + " IS NOW YOUR FRIEND"
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
				html = render_to_string("pong/add_friends_content.html", {'error_message' : {
																		'value' : True,
																		'message' : message
																}, 'users_list' : users_list,
											}, request=request)
				return JsonResponse({'html': html,
								'url' : reverse("add_friends")
					})
			else:
				return render(request, "pong/add_friends.html", {
												'error_message' : {
																		'value' : True,
																		'message' : message
																}, 'users_list' : users_list,
											})

		else:
			if friend_user is None:
				message = "this user doesn't exist"
			else:
				message = "you can't add yourself as friend"
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
					html = render_to_string("pong/add_friends_content.html", {'error_message' : {
																		'value' : True,
																		'message' : message
																}, 'users_list' : users_list,
											}, request=request)
					return JsonResponse({'html': html,
								'url' : reverse("add_friends")
					})
			else:
				return render(request, "pong/add_friends.html", {
												'error_message' : {
																		'value' : True,
																		'message' : message
																}, 'users_list' : users_list,
											})
	else:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
					html = render_to_string("pong/add_friends_content.html", {'error_message' : {
																		'value' : False,
																		'message' : "nothing"
																}, 'users_list' : users_list,
											}, request=request)
					return JsonResponse({'html': html,
								'url' : reverse("add_friends")
					})
		else:
			return render(request, "pong/add_friends.html", {
												'error_message' : {
																		'value' : False,
																		'message' : "nothing"
																}, 'users_list' : users_list,
											})




# def delete_friends(request):
	# if not request.user.is_authenticated:
	#     if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	#         html = render_to_string("pong/login_content.html", {}, request=request)
	#         return JsonResponse({'html': html})
	#     else:
	#         return HttpResponseRedirect(reverse("login"))

	# user = NewUser.objects.get(id=(request.session.get('user_id')))

	# if request.method == "POST":
	#     friend_pseudo = request.POST.get("friend_pseudo")
	#     friend_user = None
	#     try:
	#         friend_user = NewUser.objects.get(pseudo=friend_pseudo)
	#     except NewUser.DoesNotExist:
	#         friend_user = None

	#     if ( friend_user is not None) and (user.id is not friend_user.id) :
	#         friendship = Friendship.objects.filter(Q(person1=user, person2=friend_user) | Q(person1=friend_user, person2=user)).first()
	#         if friendship:
	#             friendship.delete()
	#         else:
	#             message = "you are not friends"
	#             if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	#                 html = render_to_string("pong/delete_friends_content.html", {'error_message' : {
	#                                                                     'value' : True,
	#                                                                     'message' : message
	#                                                             }
	#                                         }, request=request)
	#                 return JsonResponse({'html': html,
	#                             'url' : reverse("delete_friends")
	#                 })
	#             return render(request, "pong/delete_friends.html", {
	#                                             'error_message' : {
	#                                                                     'value' : True,
	#                                                                     'message' : message
	#                                                             }
	#                                             })


	#         #succes delete friend
	#         message = "you are not friends anymore"
	#         if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	#             html = render_to_string("pong/delete_friends_content.html", {'error_message' : {
	#                                                                     'value' : True,
	#                                                                     'message' : message
	#                                                             }
	#                                         }, request=request)
	#             return JsonResponse({'html': html,
	#                             'url' : reverse("delete_friends")
	#                 })
	#         else:
	#             return render(request, "pong/delete_friends.html", {
	#                                             'error_message' : {
	#                                                                     'value' : True,
	#                                                                     'message' : message
	#                                                             }
	#                                             })
	#     else:
	#         if friend_user is None:
	#             message = "this user doesn't exist"
	#         else:
	#             message = "you can't delete yourself as friend"

	#         if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	#             html = render_to_string("pong/delete_friends_content.html", {'error_message' : {
	#                                                                     'value' : True,
	#                                                                     'message' : message
	#                                                             }
	#                                         }, request=request)
	#             return JsonResponse({'html': html,
	#                             'url' : reverse("delete_friends")
	#                 })
	#         else:
	#             return render(request, "pong/delete_friends.html", {
	#                                             'error_message' : {
	#                                                                     'value' : True,
	#                                                                     'message' : message
	#                                                             }
	#                                             })
	# else:
	#     if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	#         html = render_to_string("pong/delete_friends_content.html", {'error_message' : {
	#                                                                     'value' : False,
	#                                                                     'message' : "nothing"
	#                                                             }
	#                                         }, request=request)
	#         return JsonResponse({'html': html,
	#                             'url' : reverse("delete_friends")
	#                 })
	#     else:
	#             return render(request, "pong/delete_friends.html", {
	#                                             'error_message' : {
	#                                                                     'value' : False,
	#                                                                     'message' : "nothing"
	#                                                             }
	#                                                             }
	#                                                             )


def delete_friends(request):
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {}, request=request)
			return JsonResponse({'html': html})
		else:
			return HttpResponseRedirect(reverse("login"))

	user = NewUser.objects.get(id=(request.session.get('user_id')))

	user_friend = get_friends(user)

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
				if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
					html = render_to_string("pong/delete_friends_content.html", {'error_message' : {
																		'value' : True,
																		'message' : message
																}, 'user_friend' : user_friend,
											}, request=request)
					return JsonResponse({'html': html,
								'url' : reverse("delete_friends")
					})
				return render(request, "pong/delete_friends.html", {
												'error_message' : {
																		'value' : True,
																		'message' : message
																}, 'user_friend' : user_friend,
												})


			#succes delete friend
			message = "you are not friends anymore"
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
				html = render_to_string("pong/delete_friends_content.html", {'error_message' : {
																		'value' : True,
																		'message' : message
																}, 'user_friend' : user_friend,
											}, request=request)
				return JsonResponse({'html': html,
								'url' : reverse("delete_friends")
					})
			else:
				return render(request, "pong/delete_friends.html", {
												'error_message' : {
																		'value' : True,
																		'message' : message
																}, 'user_friend' : user_friend,
												})
		else:
			if friend_user is None:
				message = "this user doesn't exist"
			else:
				message = "you can't delete yourself as friend"

			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
				html = render_to_string("pong/delete_friends_content.html", {'error_message' : {
																		'value' : True,
																		'message' : message
																}, 'user_friend' : user_friend,
											}, request=request)
				return JsonResponse({'html': html,
								'url' : reverse("delete_friends")
					})
			else:
				return render(request, "pong/delete_friends.html", {
												'error_message' : {
																		'value' : True,
																		'message' : message
																}, 'user_friend' : user_friend,
												})
	else:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/delete_friends_content.html", {'error_message' : {
																		'value' : False,
																		'message' : "nothing"
																}, 'user_friend' : user_friend,
											}, request=request)
			return JsonResponse({'html': html,
								'url' : reverse("delete_friends")
					})
		else:
				return render(request, "pong/delete_friends.html", {
												'error_message' : {
																		'value' : False,
																		'message' : "nothing"
																}, 'user_friend' : user_friend,
																})

def home_game(request):
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {}, request)
			return JsonResponse({'html': html, 'url' : reverse("login")})
		else:
			return HttpResponseRedirect(reverse("login"))

	if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
		html = render_to_string("pong/home_game_content.html", {}, request=request)
		return JsonResponse({'html': html, 'url' : reverse("home_game") })
	else:
		return render(request, "pong/home_game.html", {})

#################################### PONG
def waiting_pong(request):
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {}, request)
			return JsonResponse({'html': html, 'url' : reverse("login")})
		else:
			return HttpResponseRedirect(reverse("login"))

	user = request.user
	other_user = NewUser.objects.filter(in_waiting_room=True).exclude(id=user.id).first()
	if other_user:
		party = Party.objects.create(winner=user, loser=other_user, user_red=user, user_blue=other_user, game_name='Game Name', game_time=timedelta(minutes=0))
		user.in_waiting_room = False
		other_user.in_waiting_room = False
		user.save()
		other_user.save()
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/waiting_pong_content.html", {}, request=request)
			return JsonResponse({'html': html, 'url' : reverse("waiting_pong") })
		else:
			return render(request, "pong/waiting_pong.html", {})
	else:
		user.in_waiting_room = True
		user.save()
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/waiting_pong_content.html", {}, request=request)
			return JsonResponse({'html': html, 'url' : reverse("waiting_pong") })
		else:
			return render(request, "pong/waiting_pong.html", {})

def check_pong_match(request):
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {}, request)
			return JsonResponse({'html': html, 'url' : reverse("login")})
		else:
			return HttpResponseRedirect(reverse("login"))

	user = request.user
	party = Party.objects.filter(Q(user_red=user) | Q(user_blue=user), is_ended=False).last()
	if party and party.user_red and party.user_blue:
		print(" ")
		print("found OK !")
		print(" ")
		# party.user_red.in_waiting_room = False
		# party.user_blue.in_waiting_room = False
		# party.user_red.save()
		# party.user_blue.save()
		if party.user_red == user:
			return JsonResponse({
				'match_found': True,
				'party_end': party.is_ended,
				'party_id': party.id,
				'user_red': party.user_red.pseudo,
				'user_blue': party.user_blue.pseudo,
				'id_red': party.user_red.id,
				'id_blue': party.user_blue.id,
				'other_client': False
			})
		else:
			return JsonResponse({
				'match_found': False,
				'party_end': party.is_ended,
				'party_id': party.id,
				'user_red': party.user_red.pseudo,
				'user_blue': party.user_blue.pseudo,
				'id_red': party.user_red.id,
				'id_blue': party.user_blue.id,
				'other_client': True
			})

	else:
		print(" ")
		print("Nothing")
		print(" ")
		return JsonResponse({'match_found': False})

def pong_page(request, party_id):
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {}, request)
			return JsonResponse({'html': html, 'url' : reverse("login")})
		else:
			return HttpResponseRedirect(reverse("login"))

	party = get_object_or_404(Party, id=party_id)
	if party.is_ended:
		return HttpResponseRedirect(reverse("home_game"))

	if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
		if party.tournament:
			html = render_to_string("pong/pong_page_content.html", {
				'party_end': party.is_ended,
				'party_id': party.id,
				'user_red': party.user_red.pseudo,
				'user_blue': party.user_blue.pseudo,
				'alias_red': party.tournament.alias1,
				'alias_blue': party.tournament.alias2,
				'id_red': party.user_red.id,
				'id_blue': party.user_blue.id,
			}, request=request)
			return JsonResponse({'html': html, 'url' : reverse("pong_page", args=[party_id]) })
		else:
			html = render_to_string("pong/pong_page_content.html", {
				'party_end': party.is_ended,
				'party_id': party.id,
				'user_red': party.user_red.pseudo,
				'user_blue': party.user_blue.pseudo,
				'id_red': party.user_red.id,
				'id_blue': party.user_blue.id,
			}, request=request)
			return JsonResponse({'html': html, 'url' : reverse("pong_page", args=[party_id]) })
	else:
		if party.tournament:
			return render(request, 'pong/pong_page.html', {
				'party_end': party.is_ended,
				'party_id': party.id,
				'user_red': party.user_red.pseudo,
				'user_blue': party.user_blue.pseudo,
				'alias_red': party.tournament.alias1,
				'alias_blue': party.tournament.alias2,
				'id_red': party.user_red.id,
				'id_blue': party.user_blue.id,
			})
		else:
			return render(request, 'pong/pong_page.html', {
				'party_end': party.is_ended,
				'party_id': party.id,
				'user_red': party.user_red.pseudo,
				'user_blue': party.user_blue.pseudo,
				'id_red': party.user_red.id,
				'id_blue': party.user_blue.id,
			})

def scoring(request, party_id):
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {}, request)
			return JsonResponse({'html': html, 'url' : reverse("login")})
		else:
			return HttpResponseRedirect(reverse("login"))

	party = get_object_or_404(Party, id=party_id)
	if not party.is_ended:
		if (request.POST.get("red_score") > request.POST.get("blue_score")):
			party.winner = party.user_red;
			party.loser = party.user_blue;
		else:
			party.winner = party.user_blue;
			party.loser = party.user_red;
		party.winner.in_waiting_room = False;
		party.loser.in_waiting_room = False;
		party.score_red = request.POST.get("red_score");
		party.score_blue = request.POST.get("blue_score");
		party.game_time = timedelta(milliseconds=int(request.POST.get("game_time")))
		party.is_ended = True;
		party.save()
	return JsonResponse({
		'end_correctly': True,
	})

def check_game_status(request, party_id):
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {}, request)
			return JsonResponse({'html': html, 'url' : reverse("login")})
		else:
			return HttpResponseRedirect(reverse("login"))

	try:
		party = Party.objects.get(id=party_id)
		return JsonResponse({
			'party': True,
			'is_ended': party.is_ended,
			'id_party': party.id,
		})
	except ObjectDoesNotExist:
		return JsonResponse({
			'party': False,
			'is_ended': False,
			'id_party': False,
		})

def stop_waiting(request):
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {}, request)
			return JsonResponse({'html': html, 'url' : reverse("login")})
		else:
			return HttpResponseRedirect(reverse("login"))

	request.user.in_waiting_room = False;
	request.user.save()
	return JsonResponse({'everything_good': True})


###################### TOURNAMENT

def tournament(request):
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {}, request)
			return JsonResponse({'html': html, 'url' : reverse("login")})
		else:
			return HttpResponseRedirect(reverse("login"))

	if request.method == 'POST':
		alias = request.POST.get("alias")
		if not alias:
			return JsonResponse({
				'message': "the input alias cannot be empty",
			})


	# 1st IF
	tournament = Tournament.objects.filter(
		Q(participant1=request.user) |
		Q(participant2=request.user) |
		Q(participant3=request.user) |
		Q(participant4=request.user),
		winner__isnull=True
	).last()

	if tournament:
		if not tournament.participant1 or not tournament.participant2 or not tournament.participant3 or not tournament.participant4:
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
				html = render_to_string("pong/tournament_content.html", {}, request=request)
				return JsonResponse({'html': html, 'url' : reverse("tournament") })
			else:
				return render(request, "pong/tournament.html", {'message': 'Waiting for more players.'})

	# ELSE IF du cahier
	tournament = Tournament.objects.filter(
		~Q(participant1=request.user),
		~Q(participant2=request.user),
		~Q(participant3=request.user),
		~Q(participant4=request.user),
		winner__isnull=True
	).filter(
		Q(participant2__isnull=True) |
		Q(participant3__isnull=True) |
		Q(participant4__isnull=True)
	).last()


	if tournament:
		logger.debug("tournament.participant1 %s: ", tournament.participant1)
		logger.debug("tournament.participant2 %s: ", tournament.participant2)
		logger.debug("tournament.participant3 %s: ", tournament.participant3)
		logger.debug("tournament.participant4 %s: ", tournament.participant4)
		logger.info("---------------")
		if not tournament.participant2:
			if tournament.alias1 == alias:
				return JsonResponse({
					'message': "this alias is already taken",
				})
			tournament.participant2 = request.user
			tournament.alias2 = alias
		elif not tournament.participant3:
			if tournament.alias1 == alias or tournament.alias2 == alias:
				return JsonResponse({
					'message': "this alias is already taken",
				})
			tournament.participant3 = request.user
			tournament.alias3 = alias
		elif not tournament.participant4:
			if tournament.alias1 == alias or tournament.alias2 == alias or tournament.alias3 == alias:
				return JsonResponse({
					'message': "this alias is already taken",
				})
			tournament.participant4 = request.user
			tournament.alias4 = alias
		tournament.save()

		if tournament.participant1 and tournament.participant2 and tournament.participant3 and tournament.participant4:
			if not tournament.party1:
				tournament.party1 = Party.objects.create(
					winner=tournament.participant1,
					loser=tournament.participant2,
					user_red=tournament.participant1,
					user_blue=tournament.participant2,
					game_time=timedelta(minutes=0),
					tournament=tournament)
				tournament.save()
			return redirect('pong_page', party_id=tournament.party1.id)
		else:
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
				html = render_to_string("pong/tournament_content.html", {}, request=request)
				return JsonResponse({'html': html, 'url' : reverse("tournament") })
			else:
				return render(request, "pong/tournament.html", {'message': 'You have joined an existing tournament.'})

	# GROS ELSE build
	Tournament.objects.create(participant1=request.user, alias1=alias)
	if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
		html = render_to_string("pong/tournament_content.html", {}, request=request)
		return JsonResponse({'html': html, 'url' : reverse("tournament") })
	else:
		return render(request, "pong/tournament.html", {'message': 'You have created a new tournament.'})

def check_tournament_match(request):
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {}, request)
			return JsonResponse({'html': html, 'url' : reverse("login")})
		else:
			return HttpResponseRedirect(reverse("login"))

	tournament = Tournament.objects.filter(
		Q(participant1=request.user) |
		Q(participant2=request.user) |
		Q(participant3=request.user) |
		Q(participant4=request.user)
	).last()

	if tournament:
		if tournament.participant1 and tournament.participant2 and tournament.participant3 and tournament.participant4:
			return JsonResponse({
				'tournament_found': True,
			})
		else:
			return JsonResponse({
				'tournament_found': False,
			})
	else:
		return JsonResponse({
			'tournament_found': False,
		})

def scoring_next(request, party_id):
	if not request.user.is_authenticated:
		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			html = render_to_string("pong/login_content.html", {}, request)
			return JsonResponse({'html': html, 'url' : reverse("login")})
		else:
			return HttpResponseRedirect(reverse("login"))

	party = get_object_or_404(Party, id=party_id)
	if (request.POST.get("red_score") > request.POST.get("blue_score")):
		party.winner = party.user_red;
		party.loser = party.user_blue;
	else:
		party.winner = party.user_blue;
		party.loser = party.user_red;
	party.winner.in_waiting_room = False;
	party.loser.in_waiting_room = False;
	party.score_blue = request.POST.get("blue_score");
	party.score_red = request.POST.get("red_score");
	party.is_ended = True;
	party.save()

	participant1 = party.tournament.participant1
	participant2 = party.tournament.participant2
	participant3 = party.tournament.participant3
	participant4 = party.tournament.participant4

	if not party.tournament.party2:
		logger.info("party2")
		party.tournament.party2 = Party.objects.create(
			winner=participant3,
			loser=participant4,
			user_red=participant3,
			user_blue=participant4,
			game_name='Half Final',
			game_time=timedelta(minutes=0),
			tournament=party.tournament)
		party.tournament.save()
		party.save()
		logger.debug("ared: %s", party.tournament.alias3)
		logger.debug("ablue: %s", party.tournament.alias4)

		return JsonResponse({
			'end_correctly': True,
			'party_id': party.tournament.party2.id,
			'user_red': participant3.pseudo,
			'user_blue': participant4.pseudo,
			'alias_red': party.tournament.alias3,
			'alias_blue': party.tournament.alias4,
		})
	elif not party.tournament.party3:
		logger.debug("W1: %s", party.tournament.party1.winner.pseudo)
		logger.debug("W2: %s", party.tournament.party2.winner.pseudo)
		party.tournament.party3 = Party.objects.create(
			winner=party.tournament.party1.winner,
			loser=party.tournament.party2.winner,
			user_red=party.tournament.party1.winner,
			user_blue=party.tournament.party2.winner,
			game_name='Final',
			game_time=timedelta(minutes=0),
			tournament=party.tournament)
		party.tournament.save()
		party.save()
		alias_red = None
		alias_blue = None

		if party.tournament.party1.winner.pseudo == party.tournament.participant1.pseudo:
			alias_red = party.tournament.alias1
		elif party.tournament.party1.winner.pseudo == party.tournament.participant2.pseudo:
			alias_red = party.tournament.alias2
		elif party.tournament.party1.winner.pseudo == party.tournament.participant3.pseudo:
			alias_red = party.tournament.alias3
		elif party.tournament.party1.winner.pseudo == party.tournament.participant4.pseudo:
			alias_red = party.tournament.alias4

		if party.tournament.party2.winner.pseudo == party.tournament.participant1.pseudo:
			alias_blue = party.tournament.alias1
		elif party.tournament.party2.winner.pseudo == party.tournament.participant2.pseudo:
			alias_blue = party.tournament.alias2
		elif party.tournament.party2.winner.pseudo == party.tournament.participant3.pseudo:
			alias_blue = party.tournament.alias3
		elif party.tournament.party2.winner.pseudo == party.tournament.participant4.pseudo:
			alias_blue = party.tournament.alias4
		logger.debug("ared: %s", alias_red)
		logger.debug("ablue: %s", alias_blue)
		return JsonResponse({
			'end_correctly': True,
			'party_id': party.tournament.party3.id,
			'user_red': party.tournament.party1.winner.pseudo,
			'user_blue': party.tournament.party2.winner.pseudo,
			'alias_red': alias_red,
			'alias_blue': alias_blue,
		})
	elif party.tournament.party3:
		logger.info("-- -fin- --")
		party.tournament.winner = party.tournament.party3.winner
		party.tournament.save()
		party.save()

	party.save()
	return JsonResponse({
		'end_correctly': False,
		'party_id': party.id
	})





	# tournament = Tournament.objects.filter(
	# 	Q(participant1=request.user) |
	# 	Q(participant2=request.user) |
	# 	Q(participant3=request.user) |
	# 	Q(participant4=request.user)
	# ).filter(
	# 	Q(participant2__isnull=True) |
	# 	Q(participant3__isnull=True) |
	# 	Q(participant4__isnull=True)
	# ).last()

	# if tournament is None:
	# 	tournament = Tournament.objects.create(participant1=request.user)

	# if tournament.participant2 is None:
	# 	tournament.participant2 = request.user
	# elif tournament.participant3 is None:
	# 	tournament.participant3 = request.user
	# elif tournament.participant4 is None:
	# 	tournament.participant4 = request.user
	# tournament.save()

	# if tournament.participant1 is not None and tournament.participant2 is not None and tournament.participant3 is not None and tournament.participant4 is not None:
	# 	tournament.party1 = Party(
	# 		game_name="Pong Match",
	# 		game_time=timedelta(minutes=0),
	# 		user_red=tournament.participant1,
	# 		user_blue=tournament.participant2,
	# 		winner=tournament.participant1,
	# 		loser=tournament.participant2,
	# 		tournament=tournament
	# 	)
	# 	tournament.party1()
	# 	tournament.save()



	# tournament = Tournament.objects.annotate(
	# 	participant1_count=Count('participant1'),
	# 	participant2_count=Count('participant2'),
	# 	participant3_count=Count('participant3'),
	# 	participant4_count=Count('participant4')
	# ).annotate(
	# 	num_participants=F('participant1_count') + F('participant2_count') + F('participant3_count') + F('participant4_count')
	# ).order_by('num_participants').last()

	# is_participating = Tournament.objects.filter(
	# 	Q(participant1=request.user) |
	# 	Q(participant2=request.user) |
	# 	Q(participant3=request.user) |
	# 	Q(participant4=request.user)
	# ).exists()

	# if not is_participating:
	# 	Tournament.objects.create(participant1=request.user)
	# 	is_participating = True

	# if is_participating:
	# 	if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	# 		html = render_to_string("pong/tournament_content.html", {}, request=request)
	# 		return JsonResponse({'html': html, 'url' : reverse("tournament") })
	# 	else:
	# 		return render(request, "pong/tournament.html", {'message': 'Waiting for more players.'})
	# else:
	# 	if tournament is None:
	# 		tournament = Tournament.objects.create(participant1=request.user)

	# 	if tournament.participant1 is None:
	# 		tournament.participant1 = request.user
	# 	elif tournament.participant2 is None:
	# 		tournament.participant2 = request.user
	# 	elif tournament.participant3 is None:
	# 		tournament.participant3 = request.user
	# 	elif tournament.participant4 is None:
	# 		tournament.participant4 = request.user
	# 	tournament.save()

	# 	if tournament.participant1 is not None and tournament.participant2 is not None and tournament.participant3 is not None and tournament.participant4 is not None:
	# 		party = Party(
	# 			game_name="Pong Match",
	# 			game_time=timedelta(minutes=0),
	# 			user_red=tournament.participant1,
	# 			user_blue=tournament.participant2,
	# 			winner=tournament.participant1,
	# 			loser=tournament.participant2,
	# 			tournament=tournament
	# 		)
	# 		party.save()

	# 		return JsonResponse({'message': 'The tournament is full. The first match has started.'})
	# 	else:
	# 		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
	# 			html = render_to_string("pong/tournament_content.html", {}, request=request)
	# 			return JsonResponse({'html': html, 'url' : reverse("tournament") })
	# 		else:
	# 			return render(request, "pong/tournament.html", {'message': 'Waiting for more players.'})



# user_id = request.session.get('user_id')
# 	if not user_id:
# 		return HttpResponseRedirect(reverse("index"))

# 	user = get_object_or_404(NewUser.objects.select_related('statistic'), id=user_id)

# 	# Déboguer la valeur de user.statistic
# 	logger.debug("User: %s", user)
# 	logger.debug("User.statistic: %s", user.statistic)

# 	# Vérifier si user.statistic est nul ou non
# 	if user.statistic is None:
# 		logger.info("On passe la")
# 		user_statistic, created = Statistic.objects.get_or_create(user=user)
# 		user_statistic.save()
# 	else:
# 		logger.info("Statistique déjà existante")



