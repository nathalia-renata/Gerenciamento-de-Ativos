from django.db import models


#cria uma classe ativo no banco de dados
class Ativo(models.Model):
    nome = models.CharField(max_length=100) #nome do ativo
    cpf = models.CharField(max_length=14, unique=True) #cpf como id unico
    endereco = models.TextField()# endereço completo do ativo
    descricao = models.TextField()  # Descrição do ativo
    status = models.BooleanField(default=True) #ativo ou inativo
    senha = models.CharField(max_length=128)

    def __str__(self):
        return self.nome #exibe o nome do admin
    




