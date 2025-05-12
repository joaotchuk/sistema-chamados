from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_paginate import Pagination, get_page_parameter
from datetime import datetime
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.secret_key = "chave_secreta"

# Configuração do banco de dados SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chamados_ti.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Inicialização do sistema de login e criptografia
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Modelos do banco de dados
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Chamado(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(100), nullable=False)
    descricao = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="Aberto")
    prioridade = db.Column(db.String(20), default="Média")
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)

# Inicializa o banco de dados
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Rota principal: lista todos os chamados
@app.route('/')
@login_required
def index():
    page = request.args.get(get_page_parameter(), type=int, default=1)
    chamados = Chamado.query.paginate(page=page, per_page=5)
    return render_template('index.html', chamados=chamados.items, pagination=chamados)

# Rota para criar um novo chamado
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

# Rota para atualizar o status de um chamado
@app.route('/atualizar/<int:id>', methods=['GET', 'POST'])
@login_required
def atualizar_chamado(id):
    chamado = Chamado.query.get_or_404(id)
    if request.method == 'POST':
        chamado.status = request.form['status']
        chamado.prioridade = request.form['prioridade']
        db.session.commit()
        flash('Chamado atualizado com sucesso!', 'success')
        return redirect(url_for('index'))
    return render_template('atualizar_chamado.html', chamado=chamado)

# Rota para excluir um chamado
@app.route('/excluir/<int:id>')
@login_required
def excluir_chamado(id):
    chamado = Chamado.query.get_or_404(id)
    db.session.delete(chamado)
    db.session.commit()
    flash('Chamado excluído com sucesso!', 'success')
    return redirect(url_for('index'))

# Rota de registro de usuário
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        novo_usuario = User(username=username, password=password)
        db.session.add(novo_usuario)
        db.session.commit()
        flash('Usuário registrado com sucesso!', 'success')
        return redirect(url_for('login'))
    return render_template('registro.html')

# Rota de login
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

# Rota de logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você saiu da conta.', 'info')
    return redirect(url_for('login'))

# Tratamento de erros personalizados
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True)

