from django.shortcuts import render, redirect
from .models import Ativo
from validate_docbr import CPF, CNPJ
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate, login as auth_login
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from xhtml2pdf import pisa
from django.template.loader import render_to_string




# Página inicial
def index(request):
    return render(request, 'index.html')    


# View para a página de login
def login_view(request):
    if request.method == "POST":
        username = request.POST.get('username')  # Captura o nome de usuário
        senha = request.POST.get('senha')
        
        user = authenticate(request, username=username, password=senha)  # Usa o nome de usuário para autenticar

        try:
            # Procurar o usuário com o CPF
            User = get_user_model()  # Obter o modelo de usuário
            user = user.objects.get(cpf=user)
            # Agora que você tem o usuário, autentique com o campo senha
            if user.check_password(senha):  # Verifica se a senha bate
                auth_login(request, User)  # Realiza o login
                messages.success(request, "Login bem-sucedido!")
                return redirect('index')  # Redireciona para a página inicial
            else:
                messages.error(request, "Senha incorreta.")
        except User.DoesNotExist:
            messages.error(request, "Usuário não encontrado.")

    return render(request, 'login.html')


# Função para gerar o PDF
def gerar_pdf(request):
    # Pega os dados dos ativos no banco de dados
    ativos = Ativo.objects.all()

    # Renderiza o HTML com os dados da tabela
    html_string = render_to_string('lista_ativos.html', {'ativos': ativos})

    # Cria o arquivo PDF a partir do HTML
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="ativos.pdf"'

    # Converte HTML para PDF
    pisa_status = pisa.CreatePDF(html_string, dest=response)

    # Se houver algum erro na criação do PDF, exibe uma mensagem de erro
    if pisa_status.err:
        return HttpResponse('Erro ao gerar o PDF')

    return response

# Página de cadastro
def cadastro(request):
    if request.method == "POST":
        try:
            # Capturando os dados do formulário
            nome = request.POST.get('nome')
            cpf = request.POST.get('cpf', '').replace(".", "").replace("-", "").replace("/", "").strip()
            endereco = request.POST.get('endereco')
            descricao = request.POST.get('descricao')
            status = request.POST.get('status') == "ativo"
            senha = request.POST.get('senha')

            # Validação do CPF ou CNPJ
            
            """cpf_validator = CPF()
            cnpj_validator = CNPJ()
            if not (cpf_validator.validate(cpf) or cnpj_validator.validate(cpf)):
                messages.error(request, "O CPF ou CNPJ informado é inválido.")
                return render(request, 'cadastro.html', {'nome': nome, 'endereco': endereco, 'descricao': descricao})"""
           
            
            """# Validação da senha
            if not re.fullmatch(r'(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).{8,}', senha):
                messages.error(request, "A senha deve ter no mínimo 8 caracteres, incluindo uma letra maiúscula, uma letra minúscula, um número e um caractere especial (@#$%^&+=).")
                return render(request, 'cadastro.html', {'nome': nome, 'cpf': cpf, 'endereco': endereco, 'descricao': descricao})"""
            # Validação do nome
            if not nome.replace(" ", "").isalpha():
                messages.error(request, "O nome deve conter apenas letras.")
                return render(request, 'cadastro.html', {'cpf': cpf, 'endereco': endereco, 'descricao': descricao})

            # Validação do endereço
            if len(endereco) > 200:
                messages.error(request, "O endereço não pode ter mais de 200 caracteres.")
                return render(request, 'cadastro.html', {'nome': nome, 'cpf': cpf, 'descricao': descricao})

            # Validação da descrição
            if descricao and len(descricao) > 500:
                messages.error(request, "A descrição não pode ter mais de 500 caracteres.")
                return render(request, 'cadastro.html', {'nome': nome, 'cpf': cpf, 'endereco': endereco})

            # Registro no banco de dados
            Ativo.objects.create(
                nome=nome,
                cpf=cpf,
                endereco=endereco,
                descricao=descricao,
                status=status,
                senha=make_password(senha)  # Garante que a senha é armazenada de forma segura
            )
            messages.success(request, "Cadastro realizado com sucesso!")
            return redirect('login')
        except Exception as e:
            messages.error(request, f"Erro ao realizar o cadastro: {e}")
    return render(request, 'cadastro.html')


# Página de valores
def valor(request):
    return render(request, 'valor.html')


# Página de lista de ativos
def lista_ativos(request):
    ativos = Ativo.objects.all()
    return render(request, 'lista_ativos.html', {'ativos': ativos})


def login(request):
    return render(request, 'login.html')

def pagamento(request):
    return render(request, 'pagamento.html')