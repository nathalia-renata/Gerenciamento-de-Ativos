from django.urls import path
from . import views
from django.contrib.auth import views as auth_views


urlpatterns = [
    path('', views.index, name='index'),  # Conecta à view index
    path('cadastro/', views.cadastro, name='cadastro'),  # Conecta à view cadastro
    path('valor/', views.valor, name='valo'),  # Conecta à view valo
    path('ativos/', views.lista_ativos, name='lista_ativos'),  # Rota para lista de ativos
    path('login/', views.login, name='login'),  # Página de login
    path('pagamento/', views.pagamento, name='pagamento'),  # Página de pagamento
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('gerar_pdf/', views.gerar_pdf, name='gerar_pdf'),
    
]

