from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_paginate import Pagination, get_page_parameter
from datetime import datetime
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from functools import wraps

app = Flask(__name__)
app.secret_key = "chave_secreta"

import os
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    'postgresql+psycopg2://banco_kyc2_user:BxhqNWYSEN9OviYkUTliitVQ94wQ0KVw@dpg-d0h1if6uk2gs73ccht1g-a/banco_kyc2'
)




app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

from flask_migrate import Migrate

migrate = Migrate(app, db)


bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='solicitante')  # 'admin' or 'solicitante'

class Chamado(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(100), nullable=False)
    descricao = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="Aberto")
    prioridade = db.Column(db.String(20), default="Média")
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def index():
    page = request.args.get(get_page_parameter(), type=int, default=1)
    chamados = Chamado.query.paginate(page=page, per_page=5)
    return render_template('index.html', chamados=chamados.items, pagination=chamados)

@app.route('/novo', methods=['GET', 'POST'])
@login_required
def novo_chamado():
    if request.method == 'POST':
        titulo = request.form['titulo']
        descricao = request.form['descricao']
        prioridade = request.form['prioridade']
        novo_chamado = Chamado(titulo=titulo, descricao=descricao, prioridade=prioridade)
        db.session.add(novo_chamado)
        db.session.commit()
        flash('Chamado criado com sucesso!', 'success')
        return redirect(url_for('index'))
    return render_template('novo_chamado.html')

@app.route('/atualizar/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def atualizar_chamado(id):
    chamado = Chamado.query.get_or_404(id)
    if request.method == 'POST':
        chamado.status = request.form['status']
        chamado.prioridade = request.form['prioridade']
        db.session.commit()
        flash('Chamado atualizado com sucesso!', 'success')
        return redirect(url_for('index'))
    return render_template('atualizar_chamado.html', chamado=chamado)

@app.route('/excluir/<int:id>')
@login_required
@admin_required
def excluir_chamado(id):
    chamado = Chamado.query.get_or_404(id)
    db.session.delete(chamado)
    db.session.commit()
    flash('Chamado excluído com sucesso!', 'success')
    return redirect(url_for('index'))

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        role = request.form.get('role', 'solicitante')
        novo_usuario = User(username=username, password=password, role=role)
        db.session.add(novo_usuario)
        db.session.commit()
        flash('Usuário registrado com sucesso!', 'success')
        return redirect(url_for('login'))
    return render_template('registro.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Credenciais inválidas. Tente novamente.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você saiu da conta.', 'info')
    return redirect(url_for('login'))

@app.route('/admin/usuarios')
@login_required
@admin_required
def gerenciar_usuarios():
    usuarios = User.query.all()
    return render_template('usuarios.html', usuarios=usuarios)

@app.route('/admin/alterar_role/<int:id>/<nova_role>')
@login_required
@admin_required
def alterar_role(id, nova_role):
    usuario = User.query.get_or_404(id)
    if nova_role in ['admin', 'solicitante']:
        usuario.role = nova_role
        db.session.commit()
        flash(f'Permissão do usuário "{usuario.username}" atualizada para {nova_role}.', 'success')
    else:
        flash('Permissão inválida.', 'danger')
    return redirect(url_for('gerenciar_usuarios'))

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    return "<h1>403 Acesso Negado</h1><p>Você não tem permissão para acessar esta página.</p>", 403

if __name__ == '__main__':
    app.run(debug=True)
