# Atualização e Deploy do MAS - Microscopy Analysis System

Este documento contém instruções detalhadas para atualização e deploy do sistema MAS no servidor da UTFPR.

## Pré-requisitos para Deploy

- Acessar o servidor via ssh através do login e senha 

## 1. Preparação do Ambiente

### Atualização do Código

1. Faça backup do banco de dados atual:
   ```bash
   cp app/usuarios.db app/usuarios.db.backup
   ```

2. Atualize o código do repositório:
   ```bash
   git pull origin main
   ```

3. Instale novas dependências (se houver):
   ```bash
   source venv/bin/activate
   pip install -r requirements.txt
   ```

### Configuração do Ambiente Virtual

1. Crie/ative o ambiente virtual:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   pip install gunicorn
   ```

## 2. Configuração das Variáveis de Ambiente

Crie ou atualize o arquivo `.env` na raiz do projeto:

```bash
# Configurações básicas
FLASK_ENV=production
FLASK_HOST=0.0.0.0
FLASK_PORT=8000

# Chaves reCAPTCHA
RECAPTCHA_SITE_KEY=sua_site_key_aqui
RECAPTCHA_SECRET_KEY=sua_secret_key_aqui

# Configurações de Email SMTP
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=contato.masystem@gmail.com
SMTP_PASS=sua_app_password_aqui
MAIL_FROM=contato.masystem@gmail.com

# URL base da aplicação
APP_BASE_URL=https://dominio.com

# Configurações de segurança adicionais
SECRET_KEY=uma_chave_secreta_muito_forte_aqui
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
```

**Importante**: Nunca commite o arquivo `.env` no repositório. Adicione-o ao `.gitignore`.

## 3. Configuração do Banco de Dados

### Migração de Dados (se necessário)

Se houve mudanças no esquema do banco:

1. Faça backup:
   ```bash
   sqlite3 app/usuarios.db .dump > backup.sql
   ```

2. Execute migrações manuais se houver scripts em `migrations/` ou ajuste o código.

### Verificação da Integridade

```bash
python3 -c "import sqlite3; conn = sqlite3.connect('app/usuarios.db'); print('Banco OK')"
```

## 4. Configuração do Servidor Web

### Usando Gunicorn + Nginx

1. **Instale Nginx**:
   ```bash
   sudo apt update
   sudo apt install nginx
   ```

2. **Configure Nginx** (crie `/etc/nginx/sites-available/mas`):
   ```nginx
   server {
       listen 80;
       server_name seu-dominio.com www.seu-dominio.com;

       location = /favicon.ico { access_log off; log_not_found off; }
       
       location /static {
           alias /caminho/para/seu/projeto/app/static;
           expires 1y;
           add_header Cache-Control "public, immutable";
       }

       location / {
           include proxy_params;
           proxy_pass http://unix:/tmp/mas.sock;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

3. **Ative o site**:
   ```bash
   sudo ln -s /etc/nginx/sites-available/mas /etc/nginx/sites-enabled
   sudo nginx -t
   sudo systemctl reload nginx
   ```

4. **Crie serviço systemd para Gunicorn** (`/etc/systemd/system/mas.service`):
   ```ini
   [Unit]
   Description=MAS Flask App
   After=network.target

   [Service]
   User=www-data
   Group=www-data
   WorkingDirectory=/caminho/para/seu/projeto
   Environment="PATH=/caminho/para/seu/projeto/venv/bin"
   ExecStart=/caminho/para/seu/projeto/venv/bin/gunicorn --workers 3 --bind unix:/tmp/mas.sock -m 007 "app:create_app()"
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```

5. **Inicie o serviço**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl start mas
   sudo systemctl enable mas
   ```

## 5. Configuração SSL (HTTPS)

### Usando Let's Encrypt

1. **Instale Certbot**:
   ```bash
   sudo apt install certbot python3-certbot-nginx
   ```

2. **Obtenha certificado**:
   ```bash
   sudo certbot --nginx -d seu-dominio.com -d www.seu-dominio.com
   ```

3. **Renovação automática** (já configurada automaticamente).

## 6. Configuração de Firewall

```bash
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw --force enable
```

## 7. Monitoramento e Logs

### Logs da Aplicação

- **Gunicorn**: `journalctl -u mas -f`
- **Nginx**: `/var/log/nginx/error.log` e `/var/log/nginx/access.log`
- **Aplicação**: Configure logging em `app/__init__.py`

### Monitoramento Básico

1. **Verifique status dos serviços**:
   ```bash
   sudo systemctl status mas
   sudo systemctl status nginx
   ```

2. **Teste a aplicação**:
   ```bash
   curl -I https://seu-dominio.com
   ```

## 8. Backup e Recuperação

### Backup Automático

Crie um script de backup (`backup.sh`):

```bash
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/caminho/para/backups"

# Backup do banco
sqlite3 app/usuarios.db .dump > $BACKUP_DIR/db_$DATE.sql

# Backup de uploads (se houver)
tar -czf $BACKUP_DIR/uploads_$DATE.tar.gz app/static/uploads/

# Backup do código
tar -czf $BACKUP_DIR/code_$DATE.tar.gz --exclude='venv' --exclude='__pycache__' .

# Limpar backups antigos (manter últimos 7 dias)
find $BACKUP_DIR -name "*.sql" -mtime +7 -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete
```

Configure no crontab:
```bash
crontab -e
# Adicione: 0 2 * * * /caminho/para/backup.sh
```

## 9. Otimização de Performance

### Configurações do Gunicorn

- **Workers**: `número de CPUs * 2 + 1`
- **Threads**: Geralmente 1 (para apps I/O bound)
- **Timeout**: Ajuste conforme necessidade

### Cache de Arquivos Estáticos

Já configurado no Nginx acima com `expires 1y`.

### Otimização do Banco

- Use `PRAGMA journal_mode=WAL;` para melhor concorrência
- Considere índices adicionais se necessário

## 10. Troubleshooting Comum

### Aplicação não inicia
- Verifique logs: `journalctl -u mas -f`
- Teste manualmente: `source venv/bin/activate && python run.py`

### Erro 502 Bad Gateway
- Gunicorn não está rodando
- Socket não existe ou permissões incorretas

### Problemas de memória
- Monitore com `htop` ou `free -h`
- Ajuste número de workers do Gunicorn

### Emails não são enviados
- Verifique credenciais SMTP
- Teste conexão: `telnet smtp.gmail.com 587`

## 11. Rollback (se necessário)

1. **Pare a aplicação**:
   ```bash
   sudo systemctl stop mas
   ```

2. **Restaure backup**:
   ```bash
   cp app/usuarios.db.backup app/usuarios.db
   git checkout <commit-anterior>
   ```

3. **Reinicie**:
   ```bash
   sudo systemctl start mas
   ```

## 12. Checklist Final de Deploy

- [ ] Código atualizado e testado localmente
- [ ] Variáveis de ambiente configuradas
- [ ] Banco de dados migrado e testado
- [ ] Gunicorn configurado e rodando
- [ ] Nginx configurado e proxy funcionando
- [ ] SSL configurado
- [ ] Firewall ativo
- [ ] Backups automáticos configurados
- [ ] Logs monitorados
- [ ] Teste completo da aplicação
- [ ] Performance verificada

## Suporte

Em caso de problemas durante o deploy, verifique os logs e consulte a documentação do Flask/Gunicorn/Nginx. Para questões específicas do MAS, entre em contato com a equipe de desenvolvimento (lucasarruda@alunos.utfpr.edu.br).</content>
<parameter name="filePath">D:\backup\atualizacao_deploy.md
