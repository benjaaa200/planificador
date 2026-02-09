from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import secrets
import string
import hashlib
import re
import os
from datetime import datetime
import json

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Generar clave de encriptación (en producción guardar de forma segura)
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# Almacenamiento temporal (en producción usar base de datos)
users_db = {}
passwords_vault = {}
security_logs = []

# ==================== FUNCIONES DE SEGURIDAD ====================

def verificar_fortaleza_password(password):
    """Verifica la fortaleza de una contraseña"""
    score = 0
    feedback = []
    
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Debe tener al menos 8 caracteres")
    
    if len(password) >= 12:
        score += 1
    
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Debe incluir minúsculas")
    
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Debe incluir mayúsculas")
    
    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append("Debe incluir números")
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    else:
        feedback.append("Debe incluir símbolos especiales")
    
    niveles = ["Muy débil", "Débil", "Regular", "Fuerte", "Muy fuerte", "Excelente"]
    nivel = niveles[min(score, 5)]
    
    return {
        "score": score,
        "nivel": nivel,
        "feedback": feedback,
        "segura": score >= 4
    }

def generar_password_segura(longitud=16, incluir_simbolos=True):
    """Genera una contraseña segura aleatoria"""
    caracteres = string.ascii_letters + string.digits
    if incluir_simbolos:
        caracteres += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    password = ''.join(secrets.choice(caracteres) for _ in range(longitud))
    return password

def encriptar_texto(texto):
    """Encripta texto usando Fernet"""
    return cipher_suite.encrypt(texto.encode()).decode()

def desencriptar_texto(texto_encriptado):
    """Desencripta texto usando Fernet"""
    try:
        return cipher_suite.decrypt(texto_encriptado.encode()).decode()
    except:
        return None

def hash_sha256(texto):
    """Genera hash SHA-256"""
    return hashlib.sha256(texto.encode()).hexdigest()

def agregar_log(accion, usuario="Sistema", detalles=""):
    """Registra eventos de seguridad"""
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "usuario": usuario,
        "accion": accion,
        "detalles": detalles,
        "ip": request.remote_addr if request else "Local"
    }
    security_logs.append(log_entry)
    
    # Mantener solo los últimos 100 logs
    if len(security_logs) > 100:
        security_logs.pop(0)

# ==================== RUTAS ====================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if username in users_db:
        return jsonify({"success": False, "message": "Usuario ya existe"})
    
    verificacion = verificar_fortaleza_password(password)
    if not verificacion['segura']:
        return jsonify({
            "success": False, 
            "message": "Contraseña insegura",
            "feedback": verificacion['feedback']
        })
    
    # Hash de la contraseña
    password_hash = generate_password_hash(password)
    users_db[username] = {
        "password_hash": password_hash,
        "fecha_registro": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    agregar_log("Registro de usuario", username, "Nuevo usuario registrado")
    
    return jsonify({"success": True, "message": "Usuario registrado exitosamente"})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if username not in users_db:
        agregar_log("Intento de login fallido", username, "Usuario no existe")
        return jsonify({"success": False, "message": "Credenciales inválidas"})
    
    if not check_password_hash(users_db[username]['password_hash'], password):
        agregar_log("Intento de login fallido", username, "Contraseña incorrecta")
        return jsonify({"success": False, "message": "Credenciales inválidas"})
    
    session['username'] = username
    agregar_log("Login exitoso", username)
    
    return jsonify({"success": True, "message": "Login exitoso"})

@app.route('/verificar-password', methods=['POST'])
def verificar_password():
    data = request.json
    password = data.get('password')
    
    resultado = verificar_fortaleza_password(password)
    return jsonify(resultado)

@app.route('/generar-password', methods=['POST'])
def generar_password():
    data = request.json
    longitud = int(data.get('longitud', 16))
    incluir_simbolos = data.get('simbolos', True)
    
    password = generar_password_segura(longitud, incluir_simbolos)
    verificacion = verificar_fortaleza_password(password)
    
    return jsonify({
        "password": password,
        "fortaleza": verificacion
    })

@app.route('/encriptar', methods=['POST'])
def encriptar():
    data = request.json
    texto = data.get('texto')
    
    if not texto:
        return jsonify({"success": False, "message": "Texto vacío"})
    
    texto_encriptado = encriptar_texto(texto)
    
    usuario = session.get('username', 'Anónimo')
    agregar_log("Encriptación", usuario, f"Texto de {len(texto)} caracteres")
    
    return jsonify({
        "success": True,
        "texto_encriptado": texto_encriptado
    })

@app.route('/desencriptar', methods=['POST'])
def desencriptar():
    data = request.json
    texto_encriptado = data.get('texto')
    
    if not texto_encriptado:
        return jsonify({"success": False, "message": "Texto vacío"})
    
    texto_original = desencriptar_texto(texto_encriptado)
    
    if texto_original is None:
        return jsonify({"success": False, "message": "Error al desencriptar. Texto inválido."})
    
    usuario = session.get('username', 'Anónimo')
    agregar_log("Desencriptación", usuario)
    
    return jsonify({
        "success": True,
        "texto_original": texto_original
    })

@app.route('/hash', methods=['POST'])
def generar_hash():
    data = request.json
    texto = data.get('texto')
    
    if not texto:
        return jsonify({"success": False, "message": "Texto vacío"})
    
    hash_resultado = hash_sha256(texto)
    
    usuario = session.get('username', 'Anónimo')
    agregar_log("Generación de hash", usuario)
    
    return jsonify({
        "success": True,
        "hash": hash_resultado
    })

@app.route('/guardar-password', methods=['POST'])
def guardar_password():
    data = request.json
    servicio = data.get('servicio')
    usuario = data.get('usuario')
    password = data.get('password')
    
    if not all([servicio, usuario, password]):
        return jsonify({"success": False, "message": "Datos incompletos"})
    
    # Encriptar contraseña antes de guardar
    password_encriptada = encriptar_texto(password)
    
    if servicio not in passwords_vault:
        passwords_vault[servicio] = []
    
    passwords_vault[servicio].append({
        "usuario": usuario,
        "password": password_encriptada,
        "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    
    user = session.get('username', 'Anónimo')
    agregar_log("Contraseña guardada", user, f"Servicio: {servicio}")
    
    return jsonify({"success": True, "message": "Contraseña guardada de forma segura"})

@app.route('/obtener-passwords', methods=['GET'])
def obtener_passwords():
    # Desencriptar contraseñas para mostrar
    vault_desencriptado = {}
    
    for servicio, credenciales in passwords_vault.items():
        vault_desencriptado[servicio] = []
        for cred in credenciales:
            vault_desencriptado[servicio].append({
                "usuario": cred['usuario'],
                "password": desencriptar_texto(cred['password']),
                "fecha": cred['fecha']
            })
    
    return jsonify(vault_desencriptado)

@app.route('/logs', methods=['GET'])
def obtener_logs():
    return jsonify(security_logs[-50:])  # Últimos 50 logs

@app.route('/estadisticas', methods=['GET'])
def estadisticas():
    return jsonify({
        "total_usuarios": len(users_db),
        "total_passwords_guardadas": sum(len(creds) for creds in passwords_vault.values()),
        "total_logs": len(security_logs),
        "clave_encriptacion": ENCRYPTION_KEY.decode()[:20] + "..."
    })

if __name__ == '__main__':
    agregar_log("Sistema iniciado", "Sistema", "Servidor de seguridad en funcionamiento")
    print("=" * 60)
    print("🔒 SISTEMA DE CIBERSEGURIDAD INICIADO")
    print("=" * 60)
    print(f"🔑 Clave de encriptación: {ENCRYPTION_KEY.decode()[:30]}...")
    print("🌐 Servidor: http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=True, port=5000)
