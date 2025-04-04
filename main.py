import os
import subprocess
import datetime
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash  # para hash de senhas
import jwt  # para tokens JWT
import uuid  # para geração de UUID
from functools import wraps

app = Flask(__name__)

# Criar pasta de uploads
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Verificar se o ffmpeg está instalado
def check_ffmpeg_installed():
    try:
        result = subprocess.run(['which', 'ffmpeg'], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            raise EnvironmentError("ffmpeg não está instalado no sistema.")
        print("FFmpeg encontrado no sistema")
    except Exception as e:
        raise EnvironmentError(f"Erro ao verificar ffmpeg: {str(e)}")

check_ffmpeg_installed()  # Verifica se o ffmpeg está instalado

# Configurações
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key')  # Usar variáveis de ambiente
db = SQLAlchemy(app)
limiter = Limiter(app, key_func=get_remote_address)

# Criar pasta de uploads se não existir
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Modelos de dados
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(80), nullable=False)
    sobrenome = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    cpf_cnpj = db.Column(db.String(20), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    file_count = db.Column(db.Integer, default=0)
    generated_files = db.relationship('GeneratedFile', backref='user', lazy=True)

class GeneratedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

with app.app_context():
    db.drop_all()
    db.create_all()

# Funções auxiliares
def generate_video_with_audio(image_filename, mp3_filename, output_filename):
    cmd = [
        'ffmpeg',
        '-loop', '1',
        '-framerate', '2',
        '-t', '30',
        '-i', image_filename,
        '-i', mp3_filename,
        '-c:v', 'libx264',
        '-preset', 'fast',
        '-tune', 'stillimage',
        '-c:a', 'aac',
        '-b:a', '192k',
        '-shortest',
        output_filename
    ]
    subprocess.run(cmd)

def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def decode_token(token):
    try:
        return jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])['user_id']
    except:
        return None

# Decorador para exigir autenticação
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'message': 'Token é necessário'}), 403
        token = auth_header.split(' ')[1]
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
        except:
            return jsonify({'message': 'Token inválido ou expirado'}), 401
        return f(current_user, *args, **kwargs)
    return decorated_function

# Roteiros
@app.route('/login', methods=['GET'])
def login_page():
    return send_from_directory('.', 'login.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password_hash, password):
        token = generate_token(user.id)
        return jsonify({'message': 'Login bem-sucedido', 'token': token})
    return jsonify({'message': 'Credenciais inválidas'}), 401

@app.route('/check_usage', methods=['GET'])
@token_required
def check_usage(current_user):
    if current_user:
        return jsonify({
            'file_count': current_user.file_count,
            'limit': 10,
            'message': 'Uso verificado com sucesso'
        })
    return jsonify({'message': 'Usuário não encontrado'}), 404

@app.route('/generate_video', methods=['POST'])
@limiter.limit("5 per minute")
@token_required
def generate_video(current_user):
    try:
        if current_user.file_count >= 10:
            return jsonify({'message': 'Limite de arquivos atingido'}), 400

        files = os.listdir(app.config['UPLOAD_FOLDER'])
        
        image_files = [f for f in files if f.lower().endswith(('.png', '.jpg', '.jpeg', '.gif'))]
        if not image_files:
            return jsonify({'message': 'Nenhuma imagem encontrada'}), 400
        
        audio_files = [f for f in files if f.lower().endswith('.mp3')]
        if not audio_files:
            return jsonify({'message': 'Nenhum áudio encontrado'}), 400
        
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_files[-1])
        audio_path = os.path.join(app.config['UPLOAD_FOLDER'], audio_files[-1])
        
        output_filename = f'video_{uuid.uuid4().hex[:8]}.mp4'
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
        
        generate_video_with_audio(image_path, audio_path, output_path)
        
        current_user.file_count += 1
        new_file = GeneratedFile(filename=output_filename, user_id=current_user.id)
        db.session.add(new_file)
        db.session.commit()

        return jsonify({
            'message': 'Vídeo gerado com sucesso!',
            'video_url': f'/download/{output_filename}'
        })
        
    except Exception as e:
        return jsonify({'message': f'Erro ao gerar o vídeo: {str(e)}'}), 500

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/')
def index():
    return send_from_directory('.', 'login.html')

@app.route('/register', methods=['GET'])
def register_page():
    return send_from_directory('.', 'register.html')

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        required_fields = ['nome', 'sobrenome', 'email', 'cpf_cnpj', 'username', 'password']
        
        if not data or not all(field in data for field in required_fields):
            return jsonify({'message': 'Dados inválidos'}), 400

        if User.query.filter_by(username=data['username']).first():
            return jsonify({'message': 'Usuário já existe'}), 400
            
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'message': 'Email já cadastrado'}), 400
            
        if User.query.filter_by(cpf_cnpj=data['cpf_cnpj']).first():
            return jsonify({'message': 'CPF/CNPJ já cadastrado'}), 400

        hashed_password = generate_password_hash(data['password'])
        new_user = User(
            nome=data['nome'],
            sobrenome=data['sobrenome'],
            email=data['email'],
            cpf_cnpj=data['cpf_cnpj'],
            username=data['username'],
            password_hash=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'Usuário registrado com sucesso!'})
    except Exception as e:
        print(f"Erro no registro: {str(e)}")
        db.session.rollback()
        return jsonify({'message': f'Erro ao registrar: {str(e)}'}), 500

@app.route('/upload')
def upload_page():
    return send_from_directory('.', 'upload.html')

@app.route('/token')
def token_page():
    return send_from_directory('.', 'token.html')

@app.route('/paste-token')
def paste_token_page():
    return send_from_directory('.', 'paste-token.html')

@app.route('/dashboard')
def dashboard_page():
    return send_from_directory('.', 'dashboard.html')

@app.route('/download')
@app.route('/downloads')
def downloads_page():
    return send_from_directory('.', 'download.html')

@app.route('/api-docs')
def api_docs():
    return send_from_directory('.', 'api-docs.html')




@app.route('/list-uploads', methods=['GET'])
@token_required
def list_uploads(current_user):
    files = []
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        files.append({
            'filename': filename,
            'uploaded_at': datetime.datetime.fromtimestamp(
                os.path.getctime(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            ).isoformat()
        })
    return jsonify(files)

@app.route('/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    if 'audio' not in request.files and 'media' not in request.files:
        return jsonify({'detail': 'Nenhum arquivo enviado'}), 400

    files = []
    if 'audio' in request.files:
        audio = request.files['audio']
        if audio.filename:
            filename = secure_filename(audio.filename)
            audio.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            files.append(filename)

    if 'media' in request.files:
        media = request.files['media']
        if media.filename:
            filename = secure_filename(media.filename)
            media.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            files.append(filename)

    if not files:
        return jsonify({'detail': 'Nenhum arquivo válido enviado'}), 400

    return jsonify({'message': 'Upload realizado com sucesso', 'files': files})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)