from flask import Blueprint, render_template, request, redirect, url_for, session, Response
import sqlite3
import os
from ultralytics import YOLO
from PIL import Image
import base64
import io
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import traceback
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import time
import smtplib
from email.message import EmailMessage

# --- CONFIGURAÇÃO ---
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'models', 'best.pt')
model = YOLO(MODEL_PATH)
bp = Blueprint('main', __name__)
DB_PATH = os.path.join(os.path.dirname(__file__), 'usuarios.db')

# --- BANCO DE DADOS ---
"""
Garantir que a tabela `usuarios` exista e contenha a coluna `password_hash`.
Se a tabela não existir, criamos com a coluna `password_hash`.
Se a tabela existir mas não tiver a coluna, adicionamos a coluna com ALTER TABLE.
Também criamos a tabela `password_resets` para guardar tokens de redefinição de senha.
"""
with sqlite3.connect(DB_PATH) as conn:
    c = conn.cursor()
    # Cria a tabela se não existir (com a coluna password_hash)
    c.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            email TEXT NOT NULL,
            pais TEXT NOT NULL,
            organizacao TEXT NOT NULL,
            termos INTEGER NOT NULL,
            password_hash TEXT
        )
    ''')
    # Tabela para tokens de recuperação de senha
    c.execute('''
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL UNIQUE,
            expires_at INTEGER NOT NULL
        )
    ''')
    # Verifica se a coluna password_hash existe; se não, adiciona
    c.execute("PRAGMA table_info(usuarios)")
    cols = [row[1] for row in c.fetchall()]
    if 'password_hash' not in cols:
        c.execute('ALTER TABLE usuarios ADD COLUMN password_hash TEXT')
    conn.commit()


# --- ROTAS DE NAVEGAÇÃO E CADASTRO (RESTAURADAS) ---

@bp.route('/')
def index():
    return render_template('index.html')

@bp.route('/login-google')
def login_google():
    """Esta rota simula o login e redireciona para a página de cadastro."""
    return redirect(url_for('main.cadastro'))

@bp.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    """Lida com o formulário de cadastro e salva no banco de dados."""
    if request.method == 'POST':
        nome = request.form.get('nome')
        email = request.form.get('email')
        senha = request.form.get('senha')
        pais = request.form.get('pais')
        organizacao = request.form.get('organizacao')
        termos = 1 if 'termos' in request.form else 0

        # Validação mínima
        if not senha:
            erro = 'Senha é obrigatória.'
            return render_template('cadastro.html', erro=erro)

        # Hash da senha antes de salvar
        password_hash = generate_password_hash(senha)

        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute(
                'INSERT INTO usuarios (nome, email, pais, organizacao, termos, password_hash) VALUES (?, ?, ?, ?, ?, ?)',
                (nome, email, pais, organizacao, termos, password_hash)
            )
            conn.commit()
        # Após o cadastro, o usuário é levado para a página de upload (login) novo para teste
        return redirect(url_for('main.login'))

    return render_template('cadastro.html')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    """Página de login — autentica usuário e inicia sessão."""
    if request.method == 'POST':
        email = request.form.get('email')
        senha = request.form.get('senha')
        if not email or not senha:
            return render_template('login.html', erro='Email e senha são obrigatórios.')

        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute('SELECT id, email, password_hash FROM usuarios WHERE email = ?', (email,))
            row = c.fetchone()

        if not row:
            return render_template('login.html', erro='Usuário não encontrado.')

        user_id, user_email, password_hash = row
        if not password_hash:
            return render_template('login.html', erro='Senha não cadastrada para este usuário.')

        if check_password_hash(password_hash, senha):
            session['user_id'] = user_id
            session['user_email'] = user_email
            return redirect(url_for('main.upload'))
        else:
            return render_template('login.html', erro='Senha incorreta.')

    return render_template('login.html')

@bp.route('/logout')
def logout():
    """Limpa a sessão e redireciona para a página inicial."""
    session.pop('user_id', None)
    session.pop('user_email', None)
    return redirect(url_for('main.index'))

@bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Form para solicitar recuperação de senha. Gera um token e mostra o link para teste.
    Em produção você enviaria esse link por email.
    """
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            return render_template('forgot_password.html', erro='Informe o email.')

        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute('SELECT id FROM usuarios WHERE email = ?', (email,))
            row = c.fetchone()

            if not row:
                # Não vazar se o email existe — mostrar mensagem genérica
                return render_template('forgot_password.html', msg='Se o email estiver cadastrado, um link de recuperação foi gerado.')

            user_id = row[0]
            token = secrets.token_urlsafe(32)
            expires_at = int(time.time()) + 3600  # 1 hora
            c.execute('INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)', (user_id, token, expires_at))
            conn.commit()

        # constrói reset_url usando APP_BASE_URL se definido (útil em produção com domínio público)
        base = os.environ.get('APP_BASE_URL')
        if base:
            base = base.rstrip('/')
            reset_path = url_for('main.reset_password', token=token)
            reset_url = f"{base}{reset_path}"
        else:
            # fallback para host atual (útil em desenvolvimento)
            reset_url = url_for('main.reset_password', token=token, _external=True)

        # Tenta enviar por SMTP se configurado
        subject = 'Redefinição de senha - MAS'
        body_text = f'Você solicitou redefinição de senha. Acesse o link abaixo para redefinir sua senha (válido por 1 hora):\n\n{reset_url}\n\nSe não solicitou, ignore esta mensagem.'
        body_html = f"<p>Você solicitou redefinição de senha. Clique no link abaixo para redefinir sua senha (válido por 1 hora):</p><p><a href='{reset_url}'>{reset_url}</a></p><p>Se não solicitou, ignore esta mensagem.</p>"

        sent, err = send_email_smtp(email, subject, body_text, body_html)
        if sent:
            return render_template('forgot_password.html', msg='Se o email estiver cadastrado, um link de recuperação foi enviado para seu email.')
        else:
            # Falha no envio: exibimos o link para teste e a mensagem de erro
            return render_template('forgot_password.html', msg='Falha ao enviar email — link de teste abaixo:', reset_link=reset_url, send_error=err)

    return render_template('forgot_password.html')


@bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Página para redefinir a senha usando token expirável."""
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('SELECT id, user_id, expires_at FROM password_resets WHERE token = ?', (token,))
        row = c.fetchone()

    if not row:
        return render_template('reset_password.html', erro='Token inválido ou expirado.')

    reset_id, user_id, expires_at = row
    if int(time.time()) > expires_at:
        # token expirado — remover
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute('DELETE FROM password_resets WHERE id = ?', (reset_id,))
            conn.commit()
        return render_template('reset_password.html', erro='Token expirado.')

    if request.method == 'POST':
        nova = request.form.get('senha')
        if not nova or len(nova) < 6:
            return render_template('reset_password.html', erro='Senha deve ter ao menos 6 caracteres.', token=token)

        nova_hash = generate_password_hash(nova)
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute('UPDATE usuarios SET password_hash = ? WHERE id = ?', (nova_hash, user_id))
            c.execute('DELETE FROM password_resets WHERE id = ?', (reset_id,))
            conn.commit()

        return redirect(url_for('main.login'))

    return render_template('reset_password.html', token=token)

@bp.route('/upload')
def upload():
    # Não mostrar links Contato/Sobre nesta página
    return render_template('upload.html', show_contact_about=False)


# --- ROTAS DE PROCESSAMENTO E RESULTADOS (JÁ FUNCIONAIS) ---

# (A função 'criar_histograma_base64' permanece a mesma)
def criar_histograma_base64(dados, titulo, xlabel):
    # ... (código inalterado)
    if not dados: return None
    try:
        plt.figure(figsize=(8, 5))
        plt.hist(dados, bins=15, color='steelblue', edgecolor='black')
        plt.title(titulo, fontsize=16)
        plt.xlabel(xlabel, fontsize=12)
        plt.ylabel('Quantidade de Partículas', fontsize=12)
        plt.grid(axis='y', alpha=0.75)
        plt.tight_layout()
        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)
        img_base64 = base64.b64encode(buf.read()).decode('utf-8')
        plt.close()
        return img_base64
    except Exception as e:
        print(f"Erro ao criar histograma: {e}")
        return None

@bp.route('/download_txt')
def download_txt():
    txt_content = session.get('txt_data', 'Nenhum dado disponível para download.')
    return Response(
        txt_content,
        mimetype="text/plain",
        headers={"Content-Disposition":"attachment;filename=resultados_particulas.txt"}
    )

@bp.route('/processar', methods=['POST'])
def processar():
    try:
        arquivo = request.files.get('imagem')
        pixel_por_mm_str = request.form.get('pixel_por_mm', '').strip()

        # Validação: deve haver arquivo e a calibração (pixel_por_mm)
        if not arquivo or not arquivo.filename:
            return redirect(url_for('main.upload'))

        if not pixel_por_mm_str:
            # Retorna para upload com mensagem pedindo calibração
            return render_template('upload.html', erro='Por favor, calibre a imagem antes de processar (clique em "Calibrar 5mm").', show_contact_about=False)

        try:
            pixel_por_mm = float(pixel_por_mm_str.replace(',', '.'))
        except Exception:
            return render_template('upload.html', erro='Valor de calibração inválido. Por favor calibre novamente.', show_contact_about=False)

        if pixel_por_mm <= 0:
            return render_template('upload.html', erro='Calibração inválida. Por favor calibre para obter um valor maior que zero.', show_contact_about=False)

        img_original = Image.open(arquivo.stream).convert('RGB')
        img_redimensionada = img_original.resize((600, 600))
        buffer_original = io.BytesIO()
        img_redimensionada.save(buffer_original, format="JPEG")
        original_b64 = base64.b64encode(buffer_original.getvalue()).decode('utf-8')
        resultados = model.predict(img_redimensionada)
        resultado = resultados[0]
        particulas = []
        if resultado.obb is not None and len(resultado.obb) > 0:
            for box in resultado.obb:
                x, y, w, h, r = box.xywhr[0].cpu().numpy()
                comprimento_mm = w / pixel_por_mm
                largura_mm = h / pixel_por_mm
                razao_aspecto = max(comprimento_mm, largura_mm) / min(comprimento_mm, largura_mm) if min(comprimento_mm, largura_mm) > 0 else 0
                particulas.append({'id': len(particulas) + 1, 'comprimento': comprimento_mm, 'largura': largura_mm, 'razao_aspecto': razao_aspecto})
        img_proc_array = resultado.plot(labels=False, conf=False)
        img_proc_pil = Image.fromarray(img_proc_array[..., ::-1])
        buffer_proc = io.BytesIO()
        img_proc_pil.save(buffer_proc, format="JPEG")
        processada_b64 = base64.b64encode(buffer_proc.getvalue()).decode('utf-8')
        comprimentos = [p['comprimento'] for p in particulas]
        razoes = [p['razao_aspecto'] for p in particulas]
        hist_comp_b64 = criar_histograma_base64(comprimentos, 'Distribuição de Comprimento', 'Comprimento (mm)')
        hist_razao_b64 = criar_histograma_base64(razoes, 'Distribuição da Razão de Aspecto', 'Razão de Aspecto')
        txt_buffer = io.StringIO()
        txt_buffer.write("ID\tComprimento(mm)\tLargura(mm)\tRazao_Aspecto\n")
        for p in particulas:
            txt_buffer.write(f"{p['id']}\t{p['comprimento']:.4f}\t\t{p['largura']:.4f}\t\t{p['razao_aspecto']:.4f}\n")
        session['txt_data'] = txt_buffer.getvalue()
        return render_template(
            'resultado.html',
            original_b64=original_b64,
            processada_b64=processada_b64,
            pixel_por_mm=f"{pixel_por_mm:.2f}",
            qtd_particulas=len(particulas),
            particulas=particulas,
            hist_comp_b64=hist_comp_b64,
            hist_razao_b64=hist_razao_b64,
            show_contact_about=False
        )
    except Exception as e:
        error_trace = traceback.format_exc()
        return render_template('erro.html', erro=error_trace)

def send_email_smtp(to_email: str, subject: str, body_text: str, body_html: str = None) -> (bool, str):
    """Envia um email usando configuração via variáveis de ambiente.
    Variáveis esperadas (recomendado definir no ambiente):
      SMTP_HOST (default: smtp.gmail.com)
      SMTP_PORT (default: 587)
      SMTP_USER (usuário SMTP, ex: seu-email@gmail.com)
      SMTP_PASS (senha/app-password)
      MAIL_FROM (opcional, remetente; default = SMTP_USER)

    Retorna (True, "") em sucesso, (False, mensagem) em erro.
    """
    smtp_host = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
    smtp_port = int(os.environ.get('SMTP_PORT', 587))
    smtp_user = os.environ.get('SMTP_USER')
    smtp_pass = os.environ.get('SMTP_PASS')
    mail_from = os.environ.get('MAIL_FROM') or smtp_user

    if not smtp_user or not smtp_pass:
        return False, 'SMTP não configurado (defina SMTP_USER e SMTP_PASS nas variáveis de ambiente).'

    try:
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = mail_from
        msg['To'] = to_email
        if body_html:
            msg.set_content(body_text)
            msg.add_alternative(body_html, subtype='html')
        else:
            msg.set_content(body_text)

        # Suporta SMTP com TLS (porta 587) e SMTPS (porta 465)
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
        else:
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.ehlo()
                # start TLS para portas típicas (587)
                try:
                    server.starttls()
                    server.ehlo()
                except Exception:
                    pass
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)

        return True, ''
    except Exception as e:
        return False, str(e)
