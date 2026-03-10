# MAS - Microscopy Analysis System

Sistema web para processamento e análise de imagens microscópicas usando inteligência artificial desenvolvido por Lucas Arruda Silva Aluno de iniciação científica PIVIC 2024/2025.

## Visão Geral

O MAS é uma plataforma que permite aos usuários fazer upload de imagens contendo partículas de microplástico, calibrar as medições e processar as imagens utilizando um modelo YOLO treinado para detecção automática de partículas. O sistema gera análises detalhadas com medições precisas, gráficos de distribuição e exportação de dados.

## Funcionalidades Principais

- **Autenticação de Usuário**: Cadastro, login e recuperação de senha via email
- **Processamento de Imagens**: Upload e processamento de imagens microscópicas (PNG, JPG, JPEG, GIF, BMP)
- **Calibração**: Ferramenta de calibração em tempo real para precisão nas medições
- **Detecção de Partículas**: Identificação automática de partículas usando modelo YOLO
- **Análise de Dados**: Cálculo de comprimento, largura e razão de aspecto das partículas
- **Visualização**: Gráficos de distribuição (histogramas) dos dados
- **Exportação**: Download dos resultados em formato TXT
- **Limite de Taxa**: Proteção contra abuso com rate limiting
- **reCAPTCHA**: Verificação de segurança em formulários críticos

## Requisitos

- Python 3.8+
- pip (gerenciador de pacotes)
- SQLite3 (incluído no Python)

## Instalação

1. **Clone o repositório**:
   ```bash
   git clone <seu-repositorio>
   cd backup
   ```

2. **Crie um ambiente virtual**:
   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   ```

3. **Instale as dependências**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure as variáveis de ambiente**:
   Crie um arquivo `.env` na raiz do projeto:
   ```
   FLASK_ENV=development
   FLASK_HOST=0.0.0.0
   FLASK_PORT=5000
   
   # reCAPTCHA
   RECAPTCHA_SITE_KEY=seu_site_key
   RECAPTCHA_SECRET_KEY=seu_secret_key
   
   # Email SMTP (para recuperação de senha)
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USER=seu-email@gmail.com
   SMTP_PASS=sua-senha-ou-app-password
   MAIL_FROM=seu-email@gmail.com
   
   # Opcional para produção
   APP_BASE_URL=https://seu-dominio.com
   ```

## Execução

1. **Em desenvolvimento**:
   ```bash
   python run.py
   ```
   Acesse em `http://localhost:5000`

2. **Em produção** (usando Gunicorn):
   ```bash
   gunicorn -w 4 -b 0.0.0.0:5000 "app:create_app()"
   ```

## Estrutura do Projeto

```
backup/
├── app/
│   ├── __init__.py          # Factory e configuração Flask
│   ├── routes.py            # Rotas da aplicação
│   ├── models/
│   │   └── best.pt          # Modelo YOLO treinado
│   ├── usuarios.db          # Banco de dados SQLite
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css    # Estilos
│   │   ├── js/
│   │   │   └── script.js    # Scripts frontend
│   │   └── img/             # Imagens estáticas
│   └── templates/
│       ├── base.html        # Template base
│       ├── index.html       # Página inicial
│       ├── cadastro.html    # Formulário de cadastro
│       ├── login.html       # Página de login
│       ├── forgot_password.html
│       ├── reset_password.html
│       ├── upload.html      # Página de upload
│       ├── resultado.html   # Resultados análise
│       └── erro.html        # Página de erro
├── run.py                   # Ponto de entrada
├── requirements.txt         # Dependências
└── README.md               # Este arquivo
```

## Rotas Principais

| Rota | Método | Descrição |
|------|--------|-----------|
| `/` | GET | Página inicial |
| `/cadastro` | GET, POST | Formulário de cadastro |
| `/login` | GET, POST | Autenticação de usuário |
| `/logout` | GET | Encerrar sessão |
| `/forgot_password` | GET, POST | Recuperação de senha |
| `/reset_password/<token>` | GET, POST | Redefinir senha |
| `/upload` | GET | Página de upload de imagem |
| `/processar` | POST | Processar imagem e gerar análise |
| `/download_txt` | GET | Baixar resultados em TXT |

## Configuração de Email

Para enviar emails de recuperação de senha:

1. **Gmail**:
   - Use uma [App Password](https://myaccount.google.com/apppasswords) em vez da senha comum
   - Configure em `.env`:
     ```
     SMTP_HOST=smtp.gmail.com
     SMTP_PORT=587
     SMTP_USER=seu-email@gmail.com
     SMTP_PASS=sua-app-password
     ```

2. **Outros provedores SMTP**:
   - Ajuste `SMTP_HOST` e `SMTP_PORT` conforme o provedor
   - Porta 587 usa TLS; porta 465 usa SMTPS

## Configuração do reCAPTCHA

1. Acesse [Google reCAPTCHA Admin](https://www.google.com/recaptcha/admin)
2. Crie um novo site com reCAPTCHA v2
3. Copie as chaves para o arquivo `.env`

## Limites de Taxa

- **Cadastro**: 20 requisições por hora
- **Login**: 40 requisições por hora
- **Recuperação de Senha**: 40 requisições por hora
- **Processamento de Imagem**: 100 requisições por hora

Altere os valores nos decoradores `@limiter.limit()` em `routes.py` se necessário.

## Banco de Dados

O sistema usa SQLite com as seguintes tabelas:

**usuarios**:
- `id`: Identificador único
- `nome`: Nome do usuário
- `email`: Email (único)
- `pais`: País
- `organizacao`: Organização
- `termos`: Aceito dos termos (0 ou 1)
- `password_hash`: Senha criptografada

**password_resets**:
- `id`: Identificador único
- `user_id`: Referência ao usuário
- `token`: Token para resetar senha
- `expires_at`: Timestamp de expiração

## Segurança

- Senhas armazenadas com hash usando Werkzeug
- Proteção contra CSRF (via Flask-WTF, se configurado)
- Rate limiting nas rotas críticas
- Validação de reCAPTCHA
- Tokens de recuperação com expiração de 1 hora
- Validação de arquivo (extensão, tamanho, MIME type)
- Session clearing após logout

## Requisitos de Dependências

- **Flask**: Framework web
- **Ultralytics**: Modelo YOLO
- **Torch**: Deep learning (para YOLO)
- **Pillow**: Processamento de imagens
- **Matplotlib**: Geração de gráficos
- **Werkzeug**: Utilidades Flask
- **Flask-Limiter**: Rate limiting
- **python-dotenv**: Variáveis de ambiente
- **Gunicorn**: Servidor WSGI para produção

## Troubleshooting

**Erro ao fazer upload de imagem**:
- Verifique o formato (PNG, JPG, JPEG, GIF, BMP)
- Tamanho máximo: 16 MB
- Tente calibrar a imagem antes de processar

**Email de recuperação não chega**:
- Verifique variáveis `SMTP_USER` e `SMTP_PASS`
- Se usar Gmail, confirme se usou App Password
- Verifique na pasta de spam

**Modelo YOLO não carrega**:
- Confirme se `best.pt` existe em `app/models/`
- Verifique se as versões de torch e ultralytics são compatíveis

## Suporte

Para problemas ou dúvidas, entre em contato ou abra uma issue no repositório.

## Licença



