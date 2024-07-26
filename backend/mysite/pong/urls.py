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
	path('stop_waiting_pong/', views.stop_waiting_pong, name='stop_waiting_pong'),
	path('pong_page/<int:party_id>/', views.pong_page, name='pong_page'),
	path('check_pong_match/', views.check_pong_match, name='check_pong_match'),
	path('check_pong_status/<int:party_id>/', views.check_pong_status, name='check_pong_status'),
	path('scoring_pong/<int:party_id>/', views.scoring_pong, name='scoring_pong'),

	path('tournament/', views.tournament, name='tournament'),
	path('scoring_tournament/<int:party_id>/', views.scoring_tournament, name='scoring_tournament'),
	path('check_tournament_match/', views.check_tournament_match, name='check_tournament_match'),

	path('waiting_tic/', views.waiting_tic, name='waiting_tic'),
	path('stop_waiting_tic/', views.stop_waiting_tic, name='stop_waiting_tic'),
	path('tic/<int:party_id>/', views.tic, name='tic'),
	path('check_tic_match/', views.check_tic_match, name='check_tic_match'),
	path('check_tic_status/<int:party_id>/', views.check_tic_status, name='check_tic_status'),
	path('scoring_tic/<int:party_id>/', views.scoring_tic, name='scoring_tic'),

]