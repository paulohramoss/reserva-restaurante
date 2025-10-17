# Reserva Fácil

Aplicação web completa para gerenciamento de reservas de restaurante. O sistema conta com duas áreas de acesso:

- **Clientes**: realizam cadastro, efetuam login e registram reservas informando data, horário, número de pessoas e observações.
- **Gestores**: consultam todas as reservas em um painel administrativo com filtro por data.

A aplicação foi desenvolvida em Flask com persistência de dados em SQLite.

## Requisitos

- Python 3.11+
- Virtualenv (opcional, mas recomendado)

## Instalação

```bash
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate   # Windows PowerShell
pip install -r requirements.txt
```

## Executando o projeto

```bash
flask --app app run
```

O comando iniciará o servidor em `http://127.0.0.1:5000`.

## Criando contas

- **Cliente**: basta acessar a página de cadastro e escolher a opção "Cliente".
- **Gestor**: selecione "Gestor" no cadastro e informe o código de autorização padrão `GESTOR2024`.

## Estrutura do banco de dados

O banco `app.db` (SQLite) é criado automaticamente ao iniciar o servidor. Ele contém:

- `user`: informações de login e perfil (nome, e-mail, senha criptografada e tipo de conta).
- `reservation`: reservas associadas a cada cliente, incluindo data, horário, número de pessoas, observações e data de criação.

## Funcionalidades principais

- Autenticação com diferentes perfis (cliente/gestor) utilizando Flask-Login.
- Formulários validados com WTForms e mensagens amigáveis.
- Painel do gestor com tabela responsiva das reservas e filtro por data.
- Visualização do histórico de reservas por cliente.
- Interface responsiva com Bootstrap 5.

## Testando rapidamente

Para garantir que o código está íntegro você pode compilar os arquivos Python:

```bash
python -m compileall app.py
```

Isso verifica erros de sintaxe sem executar a aplicação.
