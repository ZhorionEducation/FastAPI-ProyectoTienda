from fastapi import FastAPI
from fastapi import HTTPException
from jose import JWTError, jwt
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
# se va a usar mysql como base de datos donde estan los usuarios y contraseñas
from mysql.connector import connect, Error
from datetime import datetime, timedelta
from fastapi import Depends


app = FastAPI()

# Creamos una secret key para firmar los tokens JWT
SECRET_KEY = "x9fK#2lP!q8Zs7@LmN0aB$wYtR5uE3c"
ALGORITHM = "HS256"

# Creamos un esquema de seguridad HTTP Bearer para proteger los endpoints que requieran autenticación
security = HTTPBearer()

def crear_token(data: dict):
    # Creamos un token JWT con la información del usuario y la fecha de expiración
    to_encode = data.copy()
    # el token expira en 5 minutos
    expire = datetime.utcnow() + timedelta(minutes=1)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verificar_token(token: str):
    try:
        # Verificamos el token JWT y decodificamos la información del usuario
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

# me conecto a la base de datos mysql donde estan los usuarios y contraseñas
def get_db_connection():
    try:
        connection = connect(
            host="mysql-387ba388-base-datos-mysql.l.aivencloud.com",
            user="avnadmin",
            password="AVNS_5imB7Ik3E5QV44jR009",
            database="auth_api",
            port=12739,
            connection_timeout=10,  # ← Reducir timeout
            autocommit=True  # ← Para no hacer commit manualmente
        )
        return connection
    except Error as e:
        print(f"Error al conectar a la Base de datos: {e}")
        return None

@app.get("/")

def read_index():
    return {"message": "Bienvenido a la API de autenticación"}

@app.get("/verify")
def verify_token_endpoint(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = verificar_token(token)
    return {"message": "Token válido", "user": payload["username"]}

# endpoint para registrar un nuevo usuario
@app.post("/register")
def register_user(username: str, password: str):
    connection = get_db_connection()
    if connection is None:
        raise HTTPException(status_code=500, detail="Error al conectar a la Base de datos")
    
    
    # cursor es para ejecutar las consultas a la base de datos, se le pasa la conexion para que sepa a que base de datos conectarse
    cursor = connection.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
        connection.commit()
        return {"message": "Usuario registrado exitosamente"}
    except Error as e:
        print(f"Error al registrar usuario: {e}")
        raise HTTPException(status_code=500, detail="Error al registrar usuario")
    finally:
        cursor.close()
        connection.close()

# endpoint para autenticar un usuario con JWT
@app.post("/login")
def login_user(username: str, password: str):
    connection = get_db_connection()
    if connection is None:
        raise HTTPException(status_code=500, detail="Error al conectar a la Base de datos")
    
    cursor = connection.cursor()
    try:
        # el %s es un placeholder para evitar inyecciones SQL, se le pasan los valores como una tupla 
        cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
        user = cursor.fetchone()
        if user is None:
            raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")
        
        token_data = {"username": username}
        token = crear_token(token_data)
        return {"access_token": token}
    except Error as e:
        print(f"Error al autenticar usuario: {e}")
        raise HTTPException(status_code=500, detail="Error al autenticar usuario")
    finally:
        cursor.close()
        connection.close()
        
@app.post("/logout")
def logout_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    # en este ejemplo no hacemos nada con el token, pero en una aplicación real podríamos agregarlo a una lista negra para invalidarlo
    payload = verificar_token(token)
    return {"message": "Sesión cerrada exitosamente"}
