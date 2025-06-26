# mcs-vinicius/projecttoxicos/projectToxicos-main/Backend/App.py

from flask import Flask, request, jsonify, session
from flask_mysqldb import MySQL
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import os
from functools import wraps

app = Flask(__name__)

# URL do seu frontend em produção
prod_origin = 'https://seu-projeto-na-vercel.vercel.app' 

# Configuração do CORS
CORS(
    app, 
    supports_credentials=True, 
    origins=[prod_origin, 'http://localhost:5173'] # Adicione a porta do Vite local
)

app.secret_key = os.urandom(24)

# --- Configuração do Banco de Dados ---
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'ranking_system'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor' # Retorna resultados como dicionários

mysql = MySQL(app)

# --- Decorators de Proteção de Rota ---
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

# --- Endpoints de Autenticação e Sessão ---
@app.route('/register-user', methods=['POST'])
def register_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    habby_id = data.get('habby_id')

    if not all([username, password, habby_id]):
        return jsonify({'error': 'Nome de usuário, senha e ID Habby são obrigatórios'}), 400

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE username = %s OR habby_id = %s", (username, habby_id))
    if cur.fetchone():
        return jsonify({'error': 'Nome de usuário ou ID Habby já existem.'}), 409

    cur.execute("SELECT id FROM users WHERE role = 'admin'")
    if cur.fetchone() is None:
        role = 'admin'
    else:
        role = 'member'
    
    hashed_password = generate_password_hash(password)
    
    try:
        cur.execute(
            "INSERT INTO users (username, password, role, habby_id) VALUES (%s, %s, %s, %s)",
            (username, hashed_password, role, habby_id)
        )
        user_id = cur.lastrowid
        
        cur.execute(
            "INSERT INTO user_profiles (user_id, habby_id, nick, profile_pic_url ) VALUES (%s, %s, %s, %s)",
            (user_id, habby_id, username, "https://ik.imagekit.io/wzl99vhez/toxicos/indefinido.png?updatedAt=1750707356953")
        )
        mysql.connection.commit()
        return jsonify({'message': f'Usuário cadastrado com sucesso como {role}!'}), 201
    except Exception as e:
        mysql.connection.rollback()
        return jsonify({'error': f'Erro ao cadastrar usuário: {e}'}), 500
    finally:
        cur.close()



@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, username, password, role, habby_id FROM users WHERE username = %s", [username])
    user = cur.fetchone()
    cur.close()

    if user and check_password_hash(user['password'], password):
        session['logged_in'] = True
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        session['habby_id'] = user['habby_id']
        return jsonify({
            'message': 'Login bem-sucedido!',
            'user': {
                'id': user['id'],
                'username': user['username'],
                'role': user['role'],
                'habby_id': user['habby_id']
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


# --- Endpoints de Gerenciamento de Usuários (Admin & Leader) ---
@app.route('/users', methods=['GET'])
@roles_required(['admin', 'leader'])
def get_users():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT u.id, u.username, u.role, up.habby_id, up.nick, up.profile_pic_url 
        FROM users u
        LEFT JOIN user_profiles up ON u.id = up.user_id
        ORDER BY u.role, u.username
    """)
    users = cur.fetchall()
    cur.close()
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

    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET role = %s WHERE id = %s", (new_role, user_id))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Nível de acesso atualizado com sucesso!'}), 200

@app.route('/users/<int:user_id>', methods=['DELETE'])
@roles_required(['admin', 'leader'])
def delete_user(user_id):
    logged_in_user_role = session.get('role')
    logged_in_user_id = session.get('user_id')

    if user_id == logged_in_user_id:
        return jsonify({'error': 'Você não pode excluir a si mesmo.'}), 403

    cur = mysql.connection.cursor()
    cur.execute("SELECT role FROM users WHERE id = %s", [user_id])
    user_to_delete = cur.fetchone()

    if not user_to_delete:
        return jsonify({'error': 'Usuário não encontrado.'}), 404

    if logged_in_user_role == 'leader' and user_to_delete['role'] in ['leader', 'admin']:
        return jsonify({'error': 'Líderes só podem excluir membros.'}), 403

    cur.execute("DELETE FROM users WHERE id = %s", [user_id])
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Usuário excluído com sucesso!'}), 200


# --- Endpoints de Perfil de Usuário ---
@app.route('/search-users', methods=['GET'])
@login_required
def search_users():
    query = request.args.get('query', '')
    # Não busca se a query tiver menos de 2 caracteres
    if len(query) < 2:
        return jsonify([])

    cur = mysql.connection.cursor()
    # Usa LIKE para busca parcial no nick e habby_id
    search_query = f"%{query}%"
    cur.execute("""
        SELECT up.habby_id, up.nick
        FROM user_profiles up
        WHERE up.nick LIKE %s OR up.habby_id LIKE %s
        LIMIT 10
    """, (search_query, search_query))
    users = cur.fetchall()
    cur.close()

    return jsonify(users)


@app.route('/profile/<string:habby_id>', methods=['GET'])
@login_required
def get_user_profile(habby_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM user_profiles WHERE habby_id = %s", [habby_id])
    profile = cur.fetchone()
    cur.close()
    if profile:
        return jsonify(profile), 200
    return jsonify({'error': 'Perfil não encontrado.'}), 404

@app.route('/profile', methods=['PUT'])
@login_required
def update_user_profile():
    data = request.json
    logged_in_habby_id = session.get('habby_id')

    if data.get('habby_id') != logged_in_habby_id:
        return jsonify({'error': 'Permissão negada para editar este perfil.'}), 403

    fields = [
        'nick', 'profile_pic_url', 'atk', 'hp', 'survivor_base_atk', 
        'survivor_base_hp', 'survivor_bonus_atk', 'survivor_bonus_hp', 
        'survivor_final_atk', 'survivor_final_hp', 'survivor_crit_rate', 
        'survivor_crit_damage', 'survivor_skill_damage', 'survivor_shield_boost',
        'survivor_poison_targets', 'survivor_weak_targets', 'survivor_frozen_targets',
        'pet_base_atk', 'pet_base_hp', 'pet_crit_damage', 'pet_skill_damage',
        'collect_final_atk', 'collect_final_hp', 'collect_crit_rate',
        'collect_crit_damage', 'collect_skill_damage', 'collect_poison_targets',
        'collect_weak_targets', 'collect_frozen_targets'
    ]
    
    query_parts = []
    values = []
    
    for field in fields:
        if field in data:
            query_parts.append(f"{field} = %s")
            values.append(data[field])

    if not query_parts:
        return jsonify({'error': 'Nenhum dado para atualizar.'}), 400
    
    values.append(logged_in_habby_id)
    
    query = f"UPDATE user_profiles SET {', '.join(query_parts)} WHERE habby_id = %s"
    
    cur = mysql.connection.cursor()
    cur.execute(query, values)
    mysql.connection.commit()
    cur.close()

    return jsonify({'message': 'Perfil atualizado com sucesso!'}), 200


# --- Endpoints de Temporadas e Ranking ---
@app.route('/seasons', methods=['GET'])
def get_seasons():
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, start_date, end_date FROM seasons ORDER BY start_date ASC")
    seasons = cur.fetchall()
    result = []
    for s in seasons:
        season_id = s['id']
        cur.execute(
            "SELECT id, habby_id, name, fase, r1, r2, r3, total FROM participants WHERE season_id=%s",
            (season_id,)
        )
        participants = cur.fetchall()
        result.append({**s, 'participants': participants})
    cur.close()
    return jsonify(result)

@app.route('/seasons', methods=['POST'])
@roles_required(['admin', 'leader'])
def create_season():
    data = request.json
    start_date = data.get('startDate')
    end_date = data.get('endDate')
    participants = data.get('participants', [])

    if not start_date or not end_date:
        return jsonify({'error': 'Data de início e fim obrigatórias'}), 400

    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO seasons (start_date, end_date) VALUES (%s, %s)", (start_date, end_date))
    season_id = cur.lastrowid

    for p in participants:
        cur.execute("""
            INSERT INTO participants (season_id, habby_id, name, fase, r1, r2, r3)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (season_id, p.get('habby_id'), p['name'], p['fase'], p['r1'], p['r2'], p['r3']))

    mysql.connection.commit()
    cur.close()

    return jsonify({'message': 'Temporada criada com sucesso!', 'seasonId': season_id}), 201

# Endpoint para o histórico do perfil do usuário
@app.route('/history/<string:habby_id>', methods=['GET'])
@login_required
def get_user_history(habby_id):
    try:
        cur = mysql.connection.cursor()
        
        query = """
            SELECT s.id as season_id, s.start_date, p.fase, p.total, p.name
            FROM seasons s
            JOIN participants p ON s.id = p.season_id
            WHERE p.habby_id = %s
            ORDER BY s.start_date DESC
        """
        cur.execute(query, [habby_id])
        participations = cur.fetchall()

        if not participations:
            return jsonify([]), 200

        history = []
        all_seasons_participants = {}

        for i, current in enumerate(participations):
            season_id = current['season_id']
            
            if season_id not in all_seasons_participants:
                cur.execute("SELECT fase, habby_id FROM participants WHERE season_id = %s ORDER BY fase DESC", [season_id])
                all_seasons_participants[season_id] = cur.fetchall()
            
            season_ranking = all_seasons_participants[season_id]
            position = next((i + 1 for i, p in enumerate(season_ranking) if p['habby_id'] == habby_id), None)
            
            evolution = '-'
            if i + 1 < len(participations):
                previous = participations[i + 1]
                if current.get('fase') is not None and previous.get('fase') is not None:
                    evolution = current['fase'] - previous['fase']
            
            history.append({
                'season_id': season_id,
                'start_date': current['start_date'].strftime('%Y-%m-%d'),
                'position': position,
                'fase_acesso': current['fase'],
                'evolution': evolution
            })

        cur.close()
        return jsonify(history[0] if history else {}), 200
        
    except Exception as e:
        print(f"Error fetching history: {e}")
        return jsonify({'error': 'Erro ao buscar histórico.'}), 500


# --- Endpoints da Home Page ---
@app.route('/home-content', methods=['GET'])
def get_home_content():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM home_content WHERE id = 1")
    content = cur.fetchone()
    cur.close()
    if content:
        # Converte a string de requisitos em uma lista
        content['requirements'] = content['requirements'].split(';') if content['requirements'] else []
        return jsonify(content)
    return jsonify({'error': 'Conteúdo não encontrado.'}), 404

@app.route('/home-content', methods=['PUT'])
@roles_required(['admin'])
def update_home_content():
    data = request.json
    
    # Converte a lista de requisitos de volta para uma string
    requirements = ';'.join(data.get('requirements', []))

    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE home_content SET
                leader = %s,
                focus = %s,
                league = %s,
                requirements = %s,
                about_us = %s,
                content_section = %s
            WHERE id = 1
        """, (
            data.get('leader'),
            data.get('focus'),
            data.get('league'),
            requirements,
            data.get('about_us'),
            data.get('content_section')
        ))
        mysql.connection.commit()
        return jsonify({'message': 'Conteúdo da Home atualizado com sucesso!'})
    except Exception as e:
        mysql.connection.rollback()
        return jsonify({'error': f'Erro ao atualizar conteúdo: {e}'}), 500
    finally:
        cur.close()


if __name__ == '__main__':
    app.run(debug=True, port=5000)












