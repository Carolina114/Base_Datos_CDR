import pyodbc  # Librería para conectarse a bases de datos compatibles con ODBC
import logging  # Librería para el manejo de logs
import socket  # Librería para obtener información sobre el sistema y red
import getpass  # Librería para ingresar contraseñas de manera segura
from cryptography.fernet import Fernet  # Librería para cifrar y descifrar datos de forma segura

# --------------------------- Funciones Auxiliares ---------------------------

# Función para generar el nombre de la tabla basado en el nombre del host
def get_table_name():
    try:
        # Obtiene el nombre del host (nombre del servidor)
        hostname = socket.gethostname()
        if not hostname:
            raise ValueError("El hostname no pudo ser detectado.")
        
        # Reemplaza los guiones y puntos del hostname para evitar problemas en SQL
        table_name = f"{hostname.replace('-', '_').replace('.', '_')}_cdr"  # Agrega "_cdr" al nombre
        print(f"Nombre del host detectado: {hostname}")
        print(f"Nombre de la tabla generado: {table_name}")
        return table_name
    except Exception as e:
        # Si hay un error al obtener el hostname, se loguea y se lanza un error crítico
        error_message = f"Error al obtener el hostname: {e}"
        logging.error(error_message)
        raise RuntimeError(error_message)

# Función para obtener el usuario de MySQL desde la entrada del usuario
def get_mysql_user():
    user = input("Introduce el usuario de MySQL (por defecto 'root'): ").strip()
    return user if user else "root"

# Función para obtener la contraseña de manera segura
def get_password():
    while True:
        # Solicita la contraseña sin mostrarla en la consola
        password = getpass.getpass("Introduce la contraseña de MySQL: ").strip()
        if password:  # Si la contraseña no está vacía, se retorna
            return password
        else:
            print("La contraseña no puede estar vacía. Inténtalo nuevamente.")

# Función para cargar la clave utilizada para descifrar las credenciales de Azure SQL
def load_key():
    with open("secret.key", "rb") as key_file:
        return key_file.read()  # Lee y retorna la clave secreta almacenada en el archivo

# Función para descifrar datos utilizando la clave secreta
def decrypt_data(encrypted_data, key):
    f = Fernet(key)  # Inicializa Fernet con la clave
    return f.decrypt(encrypted_data).decode()  # Descifra y decodifica el texto cifrado

# Función para cargar las credenciales de Azure SQL descifradas
def load_azure_credentials():
    key = load_key()  # Carga la clave secreta
    with open("encriptacion/encrypted_credentials.txt", "rb") as file:
        # Lee cada línea y descifra las credenciales (servidor, base de datos, usuario, contraseña)
        lines = file.readlines()
        azure_server = decrypt_data(lines[0].strip(), key)
        azure_db = decrypt_data(lines[1].strip(), key)
        azure_user = decrypt_data(lines[2].strip(), key)
        azure_password = decrypt_data(lines[3].strip(), key)
    return azure_server, azure_db, azure_user, azure_password

# --------------------------- Configuración de Logging ---------------------------
# Configura el sistema de logging para registrar eventos en un archivo de log
logging.basicConfig(
    filename='logs/estructura.log',  # Archivo donde se guardarán los logs
    level=logging.INFO,  # Nivel de los logs (INFO)
    format='%(asctime)s - %(message)s'  # Formato del mensaje del log (hora - mensaje)
)

# --------------------------- Variables de Conexión ---------------------------
# Configuración para la base de datos de origen (MySQL)
ORIGEN_HOST = socket.gethostname()  # Nombre del servidor actual
ORIGEN_USER = get_mysql_user()  # Usuario para la base de datos MySQL
ORIGEN_PASSWORD = get_password()  # Contraseña para la base de datos MySQL
ORIGEN_DB = "asteriskcdrdb"  # Nombre de la base de datos en MySQL

# Cargar las credenciales descifradas de Azure SQL
AZURE_SQL_SERVER, AZURE_SQL_DB, AZURE_SQL_USER, AZURE_SQL_PASSWORD = load_azure_credentials()

# Configuración de la cadena de conexión ODBC para Azure SQL
AZURE_SQL_CONNECTION_STRING = (
    f"DRIVER={{ODBC Driver 18 for SQL Server}};"  # Driver ODBC para SQL Server
    f"SERVER={AZURE_SQL_SERVER};"  # Servidor de Azure SQL
    f"DATABASE={AZURE_SQL_DB};"  # Base de datos de destino
    f"UID={AZURE_SQL_USER};"  # Usuario
    f"PWD={AZURE_SQL_PASSWORD};"  # Contraseña
    "Encrypt=yes;"  # Cifra la conexión
    "TrustServerCertificate=no;"  # No confía en certificados no firmados
    "Connection Timeout=30;"  # Tiempo de espera máximo para la conexión
)

# --------------------------- Script Principal ---------------------------
try:
    # Conexión a la base de datos de destino (Azure SQL)
    destino_conn = pyodbc.connect(AZURE_SQL_CONNECTION_STRING)
    destino_cursor = destino_conn.cursor()

    # Genera el nombre de la tabla basado en el hostname
    TABLE_NAME = get_table_name()

    # Verificar si la tabla ya existe
    check_table_query = f"""
    SELECT COUNT(*) 
    FROM INFORMATION_SCHEMA.TABLES 
    WHERE TABLE_NAME = '{TABLE_NAME}'
    """
    destino_cursor.execute(check_table_query)
    table_exists = destino_cursor.fetchone()[0]

    if table_exists:
        print(f"La tabla '{TABLE_NAME}' ya fue creada.")
        logging.info(f"La tabla '{TABLE_NAME}' ya existe en Azure SQL.")
    else:
        # Crear la tabla si no existe
        create_table_query = f"""
        CREATE TABLE {TABLE_NAME} (
            calldate DATETIME NOT NULL,
            clid NVARCHAR(80) NOT NULL,
            src NVARCHAR(80) NOT NULL,
            dst NVARCHAR(80) NOT NULL,
            dcontext NVARCHAR(80) NOT NULL,
            channel NVARCHAR(80) NOT NULL,
            dstchannel NVARCHAR(80) NOT NULL,
            lastapp NVARCHAR(80) NOT NULL,
            lastdata NVARCHAR(80) NOT NULL,
            duration INT NOT NULL,
            billsec INT NOT NULL,
            disposition NVARCHAR(45) NOT NULL,
            amaflags INT NOT NULL,
            accountcode NVARCHAR(20) NOT NULL,
            uniqueid NVARCHAR(32) NOT NULL,
            userfield NVARCHAR(255),
            did NVARCHAR(50),
            recordingfile NVARCHAR(255),
            cnum NVARCHAR(80),
            cnam NVARCHAR(80),
            outbound_cnum NVARCHAR(80),
            outbound_cnam NVARCHAR(80),
            dst_cnam NVARCHAR(80),
            linkedid NVARCHAR(32),
            peeraccount NVARCHAR(80),
            sequence INT
        );
        """
        destino_cursor.execute(create_table_query)
        destino_conn.commit()
        print(f"Tabla '{TABLE_NAME}' creada exitosamente.")
        logging.info(f"Tabla '{TABLE_NAME}' creada exitosamente.")

except RuntimeError as e:
    print(f"Error crítico: {e}")
    logging.error(f"Error crítico: {e}")
except Exception as e:
    logging.error(f"Error general: {str(e)}")
    print(f"Error general: {str(e)}")

finally:
    # Cierra los cursores y conexiones si están abiertos
    if 'destino_cursor' in locals():
        destino_cursor.close()
    if 'destino_conn' in locals():
        destino_conn.close()
