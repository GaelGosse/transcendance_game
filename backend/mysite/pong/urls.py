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

	path('waiting_room/', views.waiting_room, name='waiting_room'),
	path('game_page/<int:party_id>/', views.game_page, name='game_page'),
	path('check_match/', views.check_match, name='check_match'),
	path('home_game/', views.home_game, name='home_game')
]