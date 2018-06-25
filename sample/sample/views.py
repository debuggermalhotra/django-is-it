from django.http import HttpResponse
from django.conf.urls import url

DEBUG=True
SECRET_KEY = 'u&pu2b2!6m(x@dfv2lg1x9_3vkuzp3l_t9z(7a^vd6&^xbh45m'
ROOT_URLCONF = __name__
TEMPLATES=[{'BACKEND': 'django.template.backends.django.DjangoTemplates'},]

def home(request):
    
def about(request):
    

urlpatterns=[
    url(r'^$', home),
    url(r'about$',about),
    ]