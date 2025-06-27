# mcs-vinicius/projecttoxicos/projectToxicos-main/Backend/App.py

from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import os
from functools import wraps
from datetime import datetime
from sqlalchemy import or_

app = Flask(__name__)

# --- Configurações Iniciais ---
# URL do frontend em produção
prod_origin = os.environ.get('FRONTEND_URL', 'https://clatoxicos.vercel.app')

# --- ALTERAÇÃO 1: Configuração de CORS e Cookie ---
# Habilita o CORS para todas as origens durante o desenvolvimento se nenhuma URL de frontend for definida.
# Em produção, ele usará a URL do seu frontend.
# O parâmetro 'methods' foi adicionado para garantir que todos os tipos de requisição sejam permitidos.
# 'expose_headers' pode ser útil se o frontend precisar ler algum cabeçalho específico da resposta.
CORS(
    app,
    origins=prod_origin if prod_origin else "*",
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    supports_credentials=True,
    expose_headers=["Content-Type", "Authorization"]
)

# Chave secreta para a sessão
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# --- ALTERAÇÃO 2: Configuração do Cookie de Sessão ---
# Força o cookie de sessão a ser enviado em requisições de outros domínios.
# Essencial para que a autenticação funcione em navegadores como Chrome e Edge
# quando o frontend e o backend estão em domínios diferentes.
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_SECURE'] = True # 'SameSite=None' exige que o cookie seja seguro (HTTPS)

# --- Configuração do Banco de Dados (PostgreSQL via SQLAlchemy) ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Modelos do Banco de Dados (Schema) ---
# (O restante do seu código de modelos permanece o mesmo)
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='member')
    habby_id = db.Column(db.String(50), unique=True)
    profile = db.relationship('UserProfile', backref='user', uselist=False, cascade="all, delete-orphan")

class UserProfile(db.Model):
    __tablename__ = 'user_profiles'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    habby_id = db.Column(db.String(50), unique=True, nullable=False)
    nick = db.Column(db.String(100))
    profile_pic_url = db.Column(db.String(512), default="https://ik.imagekit.io/wzl99vhez/toxicos/indefinido.png?updatedAt=1750707356953")
    atk = db.Column(db.Integer)
    hp = db.Column(db.Integer)
    survivor_base_atk = db.Column(db.Integer)
    survivor_base_hp = db.Column(db.Integer)
    survivor_bonus_atk = db.Column(db.Numeric(5, 2))
    survivor_bonus_hp = db.Column(db.Numeric(5, 2))
    survivor_final_atk = db.Column(db.Integer)
    survivor_final_hp = db.Column(db.Integer)
    survivor_crit_rate = db.Column(db.Numeric(5, 2))
    survivor_crit_damage = db.Column(db.Numeric(5, 2))
    survivor_skill_damage = db.Column(db.Numeric(5, 2))
    survivor_shield_boost = db.Column(db.Numeric(5, 2))
    survivor_poison_targets = db.Column(db.Numeric(5, 2))
    survivor_weak_targets = db.Column(db.Numeric(5, 2))
    survivor_frozen_targets = db.Column(db.Numeric(5, 2))
    pet_base_atk = db.Column(db.Integer)
    pet_base_hp = db.Column(db.Integer)
    pet_crit_damage = db.Column(db.Numeric(5, 2))
    pet_skill_damage = db.Column(db.Numeric(5, 2))
    collect_final_atk = db.Column(db.Integer)
    collect_final_hp = db.Column(db.Integer)
    collect_crit_rate = db.Column(db.Numeric(5, 2))
    collect_crit_damage = db.Column(db.Numeric(5, 2))
    collect_skill_damage = db.Column(db.Numeric(5, 2))
    collect_poison_targets = db.Column(db.Numeric(5, 2))
    collect_weak_targets = db.Column(db.Numeric(5, 2))
    collect_frozen_targets = db.Column(db.Numeric(5, 2))


class Season(db.Model):
    __tablename__ = 'seasons'
    id = db.Column(db.Integer, primary_key=True)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    participants = db.relationship('Participant', backref='season', cascade="all, delete-orphan")

class Participant(db.Model):
    __tablename__ = 'participants'
    id = db.Column(db.Integer, primary_key=True)
    season_id = db.Column(db.Integer, db.ForeignKey('seasons.id', ondelete='CASCADE'), nullable=False)
    habby_id = db.Column(db.String(50))
    name = db.Column(db.String(100), nullable=False)
    fase = db.Column(db.Integer, nullable=False)
    r1 = db.Column(db.Integer, nullable=False)
    r2 = db.Column(db.Integer, nullable=False)
    r3 = db.Column(db.Integer, nullable=False)
    
    @property
    def total(self):
        return self.r1 + self.r2 + self.r3

class HomeContent(db.Model):
    __tablename__ = 'home_content'
    id = db.Column(db.Integer, primary_key=True, default=1)
    leader = db.Column(db.String(255))
    focus = db.Column(db.String(255))
    league = db.Column(db.String(255))
    requirements = db.Column(db.Text)
    about_us = db.Column(db.Text)
    content_section = db.Column(db.Text)

#USAR APENAS UMA VEZ NO PRIMEIRO DEPLOY PARA CONSTRUÇÃO DO BANCO DE DADOS
# with app.app_context():
#     db.create_all()

# --- Decorators e Endpoints ---
# (O restante do seu código de rotas permanece o mesmo)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Acesso não autorizado. Por favor, faça login.'}), 401
        return f(*args, **kwargs)
    return decorated_function

def roles_required(allowed_roles):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return jsonify({'error': 'Acesso não autorizado.'}), 401
            if session.get('role') not in allowed_roles:
                return jsonify({'error': 'Permissão insuficiente para este recurso.'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

# ... (todas as suas rotas @app.route)
@app.route('/register-user', methods=['POST'])
def register_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    habby_id = data.get('habby_id')

    if not all([username, password, habby_id]):
        return jsonify({'error': 'Nome de usuário, senha e ID Habby são obrigatórios'}), 400

    if User.query.filter((User.username == username) | (User.habby_id == habby_id)).first():
        return jsonify({'error': 'Nome de usuário ou ID Habby já existem.'}), 409

    role = 'admin' if not User.query.filter_by(role='admin').first() else 'member'
    
    hashed_password = generate_password_hash(password)
    
    try:
        new_user = User(username=username, password=hashed_password, role=role, habby_id=habby_id)
        
        new_profile = UserProfile(user=new_user, habby_id=habby_id, nick=username)
        
        db.session.add(new_user)
        db.session.add(new_profile)
        db.session.commit()
        
        return jsonify({'message': f'Usuário cadastrado com sucesso como {role}!'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Erro ao cadastrar usuário: {e}'}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password, password):
        session['logged_in'] = True
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role
        session['habby_id'] = user.habby_id
        return jsonify({
            'message': 'Login bem-sucedido!',
            'user': {
                'id': user.id,
                'username': user.username,
                'role': user.role,
                'habby_id': user.habby_id
            }
        }), 200
    else:
        return jsonify({'error': 'Credenciais inválidas'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logout bem-sucedido'}), 200

@app.route('/session', methods=['GET'])
def get_session():
    if 'user_id' in session:
        return jsonify({
            'isLoggedIn': True,
            'user': {
                'id': session['user_id'],
                'username': session['username'],
                'role': session.get('role'),
                'habby_id': session.get('habby_id')
            }
        }), 200
    return jsonify({'isLoggedIn': False}), 200


@app.route('/users', methods=['GET'])
@roles_required(['admin', 'leader'])
def get_users():
    users_data = db.session.query(
        User.id, User.username, User.role, UserProfile.habby_id, UserProfile.nick, UserProfile.profile_pic_url
    ).join(UserProfile, User.id == UserProfile.user_id).order_by(User.role, User.username).all()
    
    users = [
        {
            'id': u.id,
            'username': u.username,
            'role': u.role,
            'habby_id': u.habby_id,
            'nick': u.nick,
            'profile_pic_url': u.profile_pic_url
        } for u in users_data
    ]
    return jsonify(users), 200

@app.route('/users/<int:user_id>/role', methods=['PUT'])
@roles_required(['admin'])
def update_user_role(user_id):
    data = request.json
    new_role = data.get('role')

    if new_role not in ['member', 'leader']:
        return jsonify({'error': 'Role inválida.'}), 400

    if session.get('user_id') == user_id:
        return jsonify({'error': 'O administrador não pode alterar seu próprio nível.'}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'Usuário não encontrado.'}), 404

    try:
        user.role = new_role
        db.session.commit()
        return jsonify({'message': 'Nível de acesso atualizado com sucesso!'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Erro ao atualizar role: {e}'}), 500


@app.route('/users/<int:user_id>', methods=['DELETE'])
@roles_required(['admin', 'leader'])
def delete_user(user_id):
    logged_in_user_role = session.get('role')
    logged_in_user_id = session.get('user_id')

    if user_id == logged_in_user_id:
        return jsonify({'error': 'Você não pode excluir a si mesmo.'}), 403

    user_to_delete = User.query.get(user_id)

    if not user_to_delete:
        return jsonify({'error': 'Usuário não encontrado.'}), 404

    if logged_in_user_role == 'leader' and user_to_delete.role in ['leader', 'admin']:
        return jsonify({'error': 'Líderes só podem excluir membros.'}), 403

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        return jsonify({'message': 'Usuário excluído com sucesso!'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Erro ao excluir usuário: {e}'}), 500

@app.route('/search-users', methods=['GET'])
@login_required
def search_users():
    query = request.args.get('query', '')
    if len(query) < 2:
        return jsonify([])

    search_query = f"%{query}%"
    users = UserProfile.query.filter(
        or_(UserProfile.nick.ilike(search_query), UserProfile.habby_id.ilike(search_query))
    ).limit(10).all()

    def to_dict(profile):
        return {'habby_id': profile.habby_id, 'nick': profile.nick}
    
    return jsonify([to_dict(u) for u in users])

@app.route('/profile/<string:habby_id>', methods=['GET'])
@login_required
def get_user_profile(habby_id):
    profile = UserProfile.query.filter_by(habby_id=habby_id).first()
    if not profile:
        return jsonify({'error': 'Perfil não encontrado.'}), 404

    def to_dict(p):
        return {c.name: getattr(p, c.name) for c in p.__table__.columns}
        
    return jsonify(to_dict(profile)), 200

@app.route('/profile', methods=['PUT'])
@login_required
def update_user_profile():
    data = request.json
    logged_in_habby_id = session.get('habby_id')

    if data.get('habby_id') != logged_in_habby_id:
        return jsonify({'error': 'Permissão negada para editar este perfil.'}), 403

    profile = UserProfile.query.filter_by(habby_id=logged_in_habby_id).first()
    if not profile:
        return jsonify({'error': 'Perfil não encontrado.'}), 404

    updatable_fields = [
        'nick', 'profile_pic_url', 'atk', 'hp', 'survivor_base_atk', 'survivor_base_hp',
        'survivor_bonus_atk', 'survivor_bonus_hp', 'survivor_final_atk', 'survivor_final_hp',
        'survivor_crit_rate', 'survivor_crit_damage', 'survivor_skill_damage',
        'survivor_shield_boost', 'survivor_poison_targets', 'survivor_weak_targets',
        'survivor_frozen_targets', 'pet_base_atk', 'pet_base_hp', 'pet_crit_damage',
        'pet_skill_damage', 'collect_final_atk', 'collect_final_hp', 'collect_crit_rate',
        'collect_crit_damage', 'collect_skill_damage', 'collect_poison_targets',
        'collect_weak_targets', 'collect_frozen_targets'
    ]
    
    updated = False
    for field in updatable_fields:
        if field in data:
            setattr(profile, field, data[field])
            updated = True
    
    if not updated:
        return jsonify({'error': 'Nenhum dado para atualizar.'}), 400

    try:
        db.session.commit()
        return jsonify({'message': 'Perfil atualizado com sucesso!'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Erro ao atualizar perfil: {e}'}), 500

@app.route('/seasons', methods=['GET'])
def get_seasons():
    seasons = Season.query.order_by(Season.start_date.asc()).all()
    
    result = []
    for s in seasons:
        participants_data = [
            {
                'id': p.id, 'habby_id': p.habby_id, 'name': p.name, 'fase': p.fase,
                'r1': p.r1, 'r2': p.r2, 'r3': p.r3, 'total': p.total
            } for p in s.participants
        ]
        result.append({
            'id': s.id,
            'start_date': s.start_date.isoformat(),
            'end_date': s.end_date.isoformat(),
            'participants': participants_data
        })
        
    return jsonify(result)

@app.route('/seasons', methods=['POST'])
@roles_required(['admin', 'leader'])
def create_season():
    data = request.json
    start_date_str = data.get('startDate')
    end_date_str = data.get('endDate')
    participants_data = data.get('participants', [])

    if not start_date_str or not end_date_str:
        return jsonify({'error': 'Data de início e fim obrigatórias'}), 400

    try:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        
        new_season = Season(start_date=start_date, end_date=end_date)
        db.session.add(new_season)
        db.session.flush()

        for p_data in participants_data:
            new_participant = Participant(
                season_id=new_season.id, habby_id=p_data.get('habby_id'),
                name=p_data['name'], fase=p_data['fase'], r1=p_data['r1'],
                r2=p_data['r2'], r3=p_data['r3']
            )
            db.session.add(new_participant)
            
        db.session.commit()
        return jsonify({'message': 'Temporada criada com sucesso!', 'seasonId': new_season.id}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Erro ao criar temporada: {e}'}), 500

@app.route('/seasons/<int:season_id>', methods=['DELETE'])
@roles_required(['admin']) # 1. Protege a rota, apenas admins podem acessar
def delete_season(season_id):
    # 2. Busca a temporada no banco de dados pelo ID fornecido na URL
    season_to_delete = Season.query.get(season_id)

    # 3. Verifica se a temporada realmente existe
    if not season_to_delete:
        return jsonify({'error': 'Temporada não encontrada.'}), 404

    try:
        # 4. Deleta a temporada. 
        # Graças ao 'cascade="all, delete-orphan"' no seu modelo, 
        # todos os participantes associados a esta temporada serão excluídos automaticamente.
        db.session.delete(season_to_delete)
        
        # 5. Confirma a transação no banco de dados
        db.session.commit()
        
        return jsonify({'message': 'Temporada e todos os seus registros foram excluídos com sucesso!'}), 200
    except Exception as e:
        # Em caso de erro, reverte a transação para não corromper o banco
        db.session.rollback()
        return jsonify({'error': f'Erro ao excluir a temporada: {e}'}), 500

@app.route('/history/<string:habby_id>', methods=['GET'])
@login_required
def get_user_history(habby_id):
    try:
        participations = db.session.query(
            Season.id.label('season_id'), Season.start_date, Participant.fase,
            (Participant.r1 + Participant.r2 + Participant.r3).label('total'), Participant.name
        ).join(Participant, Season.id == Participant.season_id)\
         .filter(Participant.habby_id == habby_id)\
         .order_by(Season.start_date.desc()).all()

        if not participations:
            return jsonify([]), 200

        history = []
        for i, current in enumerate(participations):
            season_id = current.season_id
            season_ranking = Participant.query.filter_by(season_id=season_id)\
                                              .order_by(Participant.fase.desc()).all()
            position = next((idx + 1 for idx, p in enumerate(season_ranking) if p.habby_id == habby_id), None)
            
            evolution = '-'
            if i + 1 < len(participations):
                previous = participations[i + 1]
                if current.fase is not None and previous.fase is not None:
                    evolution = current.fase - previous.fase
            
            history.append({
                'season_id': season_id, 'start_date': current.start_date.strftime('%Y-%m-%d'),
                'position': position, 'fase_acesso': current.fase, 'evolution': evolution
            })

        return jsonify(history[0] if history else {}), 200
        
    except Exception as e:
        print(f"Error fetching history: {e}")
        return jsonify({'error': 'Erro ao buscar histórico.'}), 500

@app.route('/home-content', methods=['GET'])
def get_home_content():
    content = HomeContent.query.get(1)
    if content:
        requirements_list = content.requirements.split(';') if content.requirements else []
        return jsonify({
            'leader': content.leader,
            'focus': content.focus,
            'league': content.league,
            'requirements': requirements_list,
            'about_us': content.about_us,
            'content_section': content.content_section,
        })
        
    return jsonify({'error': 'Conteúdo não encontrado.'}), 404

@app.route('/home-content', methods=['PUT'])
@roles_required(['admin'])
def update_home_content():
    data = request.json
    content = HomeContent.query.get(1)
    if not content:
        return jsonify({'error': 'Conteúdo não encontrado para atualizar.'}), 404

    requirements_str = ';'.join(data.get('requirements', []))
    
    try:
        content.leader = data.get('leader')
        content.focus = data.get('focus')
        content.league = data.get('league')
        content.requirements = requirements_str
        content.about_us = data.get('about_us')
        content.content_section = data.get('content_section')
        
        db.session.commit()
        return jsonify({'message': 'Conteúdo da Home atualizado com sucesso!'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Erro ao atualizar conteúdo: {e}'}), 500


def create_tables():
    with app.app_context():
        print("Criando tabelas no banco de dados...")
        db.create_all()
        print("Tabelas criadas com sucesso.")

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'init-db':
        create_tables()
    else:
        app.run(debug=True, port=int(os.environ.get('PORT', 5000)))