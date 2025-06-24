import os
import secrets
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message

# Configurações básicas
app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua-chave-secreta-aqui'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['MAIL_SERVER'] = 'smtp.seuprovedor.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'seu@email.com'
app.config['MAIL_PASSWORD'] = 'suasenha'
app.config['MAIL_DEFAULT_SENDER'] = 'seu@email.com'
app.config['SECURITY_PASSWORD_SALT'] = 'um-sal-seguro'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Extensões
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)


# Modelos
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    reset_token = db.Column(db.String(100))
    reset_token_expiration = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_reset_token(self):
        self.reset_token = secrets.token_urlsafe(32)
        self.reset_token_expiration = datetime.utcnow() + timedelta(hours=1)
        db.session.commit()
        return self.reset_token


class Arquivo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome_arquivo = db.Column(db.String(200), nullable=False)
    caminho = db.Column(db.String(200), nullable=False)
    data_envio = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


# Login manager
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# Rotas principais
@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()

        if user and user.check_password(password):
            login_user(user)
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        flash('Credenciais inválidas', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Sessão encerrada.', 'info')
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none():
            flash('Nome de usuário já existe', 'danger')
            return redirect(url_for('register'))

        if db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none():
            flash('Email já está em uso', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registro realizado com sucesso!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form['email']
        user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none()
        if user:
            token = user.generate_reset_token()
            reset_url = url_for('reset_password', token=token, _external=True)

            msg = Message('Redefinição de Senha', recipients=[user.email])
            msg.body = f'''Clique no link para redefinir sua senha:
{reset_url}

Se você não solicitou isso, ignore este email. O link expira em 1 hora.'''
            try:
                mail.send(msg)
                flash('Um email com instruções foi enviado.', 'info')
            except:
                flash('Erro ao enviar email.', 'danger')
            return redirect(url_for('login'))
        flash('Email não encontrado.', 'danger')

    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    user = db.session.execute(db.select(User).filter_by(reset_token=token)).scalar_one_or_none()
    if not user or user.reset_token_expiration < datetime.utcnow():
        flash('Token inválido ou expirado.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm_password']
        if password != confirm:
            flash('As senhas não coincidem.', 'danger')
        else:
            user.set_password(password)
            user.reset_token = None
            user.reset_token_expiration = None
            db.session.commit()
            flash('Senha redefinida com sucesso!', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        arquivo = request.files.get('arquivo')
        if arquivo:
            nome_seguro = secure_filename(arquivo.filename)
            caminho_arquivo = os.path.join(app.config['UPLOAD_FOLDER'], nome_seguro)
            arquivo.save(caminho_arquivo)

            novo_arquivo = Arquivo(nome_arquivo=nome_seguro, caminho=caminho_arquivo, user_id=current_user.id)
            db.session.add(novo_arquivo)
            db.session.commit()
            flash('Arquivo enviado com sucesso!', 'success')
            return redirect(url_for('dashboard'))

    arquivos_usuario = Arquivo.query.filter_by(user_id=current_user.id).all()
    todos_usuarios = User.query.all() if current_user.is_admin else []

    return render_template('dashboard.html', user=current_user, arquivos=arquivos_usuario, usuarios=todos_usuarios)


@app.route('/uploads/<path:filename>')
@login_required
def download_arquivo(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


# Rotas de administração
@app.route('/admin/usuarios')
@login_required
def admin_usuarios():
    if not current_user.is_admin:
        flash('Acesso negado. Apenas administradores podem acessar esta página.', 'danger')
        return redirect(url_for('dashboard'))

    usuarios = User.query.order_by(User.username).all()
    return render_template('admin_usuarios.html', usuarios=usuarios)


@app.route('/admin/usuario/<int:user_id>/toggle_admin', methods=['POST'])
@login_required
def toggle_admin(user_id):
    if not current_user.is_admin:
        flash('Acesso negado. Apenas administradores podem realizar esta ação.', 'danger')
        return redirect(url_for('dashboard'))

    user = db.session.get(User, user_id)
    if user and user != current_user:
        user.is_admin = not user.is_admin
        db.session.commit()
        action = "concedida" if user.is_admin else "revogada"
        flash(f'Permissão de administrador {action} para o usuário {user.username}.', 'success')
    elif user == current_user:
        flash('Você não pode alterar suas próprias permissões de administrador.', 'warning')
    else:
        flash('Usuário não encontrado.', 'danger')

    return redirect(url_for('admin_usuarios'))


@app.route('/admin/usuario/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Acesso negado. Apenas administradores podem realizar esta ação.', 'danger')
        return redirect(url_for('dashboard'))

    user = db.session.get(User, user_id)
    if user and user != current_user:
        # Primeiro deleta os arquivos do usuário
        Arquivo.query.filter_by(user_id=user_id).delete()
        # Depois deleta o usuário
        db.session.delete(user)
        db.session.commit()
        flash(f'Usuário {user.username} e todos os seus arquivos foram removidos com sucesso.', 'success')
    elif user == current_user:
        flash('Você não pode deletar sua própria conta.', 'warning')
    else:
        flash('Usuário não encontrado.', 'danger')

    return redirect(url_for('admin_usuarios'))


# Inicializador
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not db.session.execute(db.select(User).filter_by(username='admin')).scalar_one_or_none():
            admin = User(username='admin', email='admin@example.com', is_admin=True)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print('✅ Admin criado: usuário "admin", senha "admin123"')
    app.run(debug=True)