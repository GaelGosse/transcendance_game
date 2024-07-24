from django.urls import path, include
#from two_factor.urls import urlpatterns as tf_urls

from . import views

urlpatterns = [
	path("", views.index, name="index"),
	path("signup", views.signup, name ="signup"),
	path("signin", views.signin, name="signin"),
	path("login", views.login_view, name="login"),
	path("logout", views.logout_view, name="logout"),
	path("statistics/", views.statistics, name="statistics"),
	path("chat/", views.chat, name="chat"),
	path("otp/", views.otp_view, name="otp"),
	path("profile", views.profile_view, name = "profile"),
	path("add_friends", views.add_friends, name ="add_friends"),
	path("delete_friends", views.delete_friends, name = "delete_friends"),

	path('home_game/', views.home_game, name='home_game'),

	path('waiting_pong/', views.waiting_pong, name='waiting_pong'),
	path('stop_waiting/', views.stop_waiting, name='stop_waiting'),
	path('pong_page/<int:party_id>/', views.pong_page, name='pong_page'),
	path('check_pong_match/', views.check_pong_match, name='check_pong_match'),
	path('check_game_status/<int:party_id>/', views.check_game_status, name='check_game_status'),
	path('scoring/<int:party_id>/', views.scoring, name='scoring'),

	path('tournament/', views.tournament, name='tournament'),
	path('scoring_next/<int:party_id>/', views.scoring_next, name='scoring_next'),
	path('check_tournament_match/', views.check_tournament_match, name='check_tournament_match'),
]