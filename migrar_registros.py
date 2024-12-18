import pyodbc  # Librería para conectar con SQL Server (ODBC).
import mysql.connector  # Librería para conectar con MySQL.
import logging  # Librería para crear logs.
import socket  # Librería para obtener información de la red (hostname).
import getpass  # Librería para solicitar contraseñas de forma segura.
from cryptography.fernet import Fernet  # Librería para desencriptar datos.

# --------------------------- Funciones Auxiliares ---------------------------

# Función para obtener el nombre de la tabla basado en el hostname
def get_table_name():
    hostname = socket.gethostname()
    table_name = f"{hostname.replace('-', '_').replace('.', '_')}_cdr"
    print(f"Nombre de la tabla generado: {table_name}")
    return table_name

# Función para cargar la clave de encriptación
def load_key():
    with open("secret.key", "rb") as key_file:
        return key_file.read()

# Función para desencriptar los datos
def decrypt_data(encrypted_data, key):
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode()

# Función para cargar credenciales desencriptadas
def load_azure_credentials():
    key = load_key()
    with open("encriptacion/encrypted_credentials.txt", "rb") as file:
        lines = file.readlines()
        azure_server = decrypt_data(lines[0].strip(), key)
        azure_db = decrypt_data(lines[1].strip(), key)
        azure_user = decrypt_data(lines[2].strip(), key)
        azure_password = decrypt_data(lines[3].strip(), key)
    return azure_server, azure_db, azure_user, azure_password

# --------------------------- Configuración de Logging ---------------------------
logging.basicConfig(
    filename='logs/sincronizacion_inicial.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)
# Función para solicitar la contraseña de MySQL y validarla
def get_mysql_credentials():
    while True:
        user = input("Introduce el usuario de MySQL (por defecto 'root'): ").strip() or "root"
        password = getpass.getpass("Introduce la contraseña de MySQL: ").strip()
        if not password:
            print("La contraseña es obligatoria. Por favor, intenta de nuevo.")
            continue
        
        # Intentar una conexión de prueba para validar las credenciales
        try:
            mysql.connector.connect(
                host=socket.gethostname(), user=user, password=password
            )
            print("Credenciales correctas.")
            return user, password
        except mysql.connector.Error:
            print("Contraseña incorrecta. Por favor, inténtalo de nuevo.")
# --------------------------- Variables de Conexión ---------------------------
# Credenciales de Azure SQL
AZURE_SQL_SERVER, AZURE_SQL_DB, AZURE_SQL_USER, AZURE_SQL_PASSWORD = load_azure_credentials()
AZURE_SQL_CONNECTION_STRING = (
    f"DRIVER={{ODBC Driver 18 for SQL Server}};"
    f"SERVER={AZURE_SQL_SERVER};"
    f"DATABASE={AZURE_SQL_DB};"
    f"UID={AZURE_SQL_USER};"
    f"PWD={AZURE_SQL_PASSWORD};"
    "Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;"
)

# Solicitar credenciales de MySQL
ORIGEN_USER, ORIGEN_PASSWORD = get_mysql_credentials()
ORIGEN_DB = "asteriskcdrdb"

# --------------------------- Migración de Registros ---------------------------
def sincronizar_registros():
    try:
        # Conexión a MySQL (Origen)
        origen_conn = mysql.connector.connect(
            host=socket.gethostname(), user=ORIGEN_USER, password=ORIGEN_PASSWORD, database=ORIGEN_DB
        )
        origen_cursor = origen_conn.cursor(dictionary=True)

        # Conexión a Azure SQL (Destino)
        destino_conn = pyodbc.connect(AZURE_SQL_CONNECTION_STRING)
        destino_cursor = destino_conn.cursor()

        TABLE_NAME = get_table_name()

        # 1. Verificar si la tabla ya tiene registros
        query_check_table = f"SELECT COUNT(*) FROM {TABLE_NAME};"
        destino_cursor.execute(query_check_table)
        total_registros = destino_cursor.fetchone()[0]

        if total_registros > 0:
            mensaje = f"Los registros ya fueron migrados previamente. Total registros en Azure: {total_registros}"
            print(mensaje)
            logging.info(mensaje)
            return  # Termina el script sin hacer nada más

        # 2. Consultar registros de los últimos 4 meses en MySQL
        logging.info("Consultando registros de los últimos 4 meses...")
        consulta_mysql = """
            SELECT * FROM cdr 
            WHERE calldate >= DATE_SUB(CURDATE(), INTERVAL 4 MONTH);
        """
        origen_cursor.execute(consulta_mysql)
        registros = origen_cursor.fetchall()

        if not registros:
            print("No hay registros nuevos para migrar.")
            logging.info("No hay registros nuevos para migrar.")
            return

        print(f"Se encontraron {len(registros)} registros para migrar. Iniciando migración...")
        logging.info(f"Se encontraron {len(registros)} registros para migrar.")

        # 3. Insertar registros en Azure SQL
        insert_query = f"""
            INSERT INTO {TABLE_NAME} (
                calldate, clid, src, dst, dcontext, channel, dstchannel, lastapp, lastdata, duration,
                billsec, disposition, amaflags, accountcode, uniqueid, userfield, did, recordingfile,
                cnum, cnam, outbound_cnum, outbound_cnam, dst_cnam, linkedid, peeraccount, sequence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        for idx, fila in enumerate(registros):
            valores = (
                fila['calldate'], fila['clid'], fila['src'], fila['dst'], fila['dcontext'],
                fila['channel'], fila['dstchannel'], fila['lastapp'], fila['lastdata'], fila['duration'],
                fila['billsec'], fila['disposition'], fila['amaflags'], fila['accountcode'], fila['uniqueid'],
                fila['userfield'], fila['did'], fila['recordingfile'], fila['cnum'], fila['cnam'],
                fila['outbound_cnum'], fila['outbound_cnam'], fila['dst_cnam'], fila['linkedid'],
                fila['peeraccount'], fila['sequence']
            )
            destino_cursor.execute(insert_query, valores)
            logging.info(f"Registro {idx + 1} migrado: {valores}")

        destino_conn.commit()
        print("Migración completada exitosamente.")
        logging.info("Migración completada exitosamente.")

    except Exception as e:
        print(f"Error general: {e}")
        logging.error(f"Error general: {e}")

    finally:
        if 'origen_cursor' in locals(): origen_cursor.close()
        if 'origen_conn' in locals(): origen_conn.close()
        if 'destino_cursor' in locals(): destino_cursor.close()
        if 'destino_conn' in locals(): destino_conn.close()

# --------------------------- Ejecución Principal ---------------------------
if __name__ == "__main__":
    sincronizar_registros()
