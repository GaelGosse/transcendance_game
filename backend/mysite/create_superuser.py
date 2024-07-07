import os
import django
from django.contrib.auth import get_user_model
from django.core.management import BaseCommand

class Command(BaseCommand):
	def handle(self, *args, **options):
		os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mysite.settings')
		django.setup()
		User = get_user_model()
		if not User.objects.filter(pseudo='admin').exists():
			User.objects.create_superuser(email='admin@example.com', pseudo='admin', password='adminpassword')

if __name__ == "__main__":
	Command().handle()