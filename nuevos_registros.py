import pyodbc  # Para conectar con Azure SQL
import mysql.connector  # Para conectar con MySQL
import logging  # Para manejo de logs
import socket  # Para obtener información del servidor local
import getpass  # Para ingresar contraseñas de manera segura
from cryptography.fernet import Fernet  # Para desencriptar datos
from datetime import datetime

# --------------------------- Funciones Auxiliares ---------------------------

# Función para cargar la clave secreta
def load_key():
    with open("secret.key", "rb") as key_file:
        return key_file.read()

# Función para desencriptar datos
def decrypt_data(encrypted_data, key):
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode()

# Función para cargar credenciales desencriptadas
def load_credentials():
    key = load_key()
    with open("encriptacion/encrypted_credentials.txt", "rb") as file:
        lines = file.readlines()
        azure_server = decrypt_data(lines[0].strip(), key)
        azure_db = decrypt_data(lines[1].strip(), key)
        azure_user = decrypt_data(lines[2].strip(), key)
        azure_password = decrypt_data(lines[3].strip(), key)
    return azure_server, azure_db, azure_user, azure_password

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

# Función para generar el nombre de la tabla
def get_table_name():
    hostname = socket.gethostname()
    return f"{hostname.replace('-', '_').replace('.', '_')}_cdr"

# --------------------------- Configuración de Logging ---------------------------
# Logger para la sincronización de registros
sync_logger = logging.getLogger("sync_logger")
sync_logger.setLevel(logging.INFO)
sync_handler = logging.FileHandler('logs/nuevos_registros.log')
sync_formatter = logging.Formatter('%(asctime)s - %(message)s')
sync_handler.setFormatter(sync_formatter)
sync_logger.addHandler(sync_handler)

# Logger para la limpieza de registros antiguos
cleanup_logger = logging.getLogger("cleanup_logger")
cleanup_logger.setLevel(logging.INFO)
cleanup_handler = logging.FileHandler('logs/limpieza_mes_antiguo.log')
cleanup_formatter = logging.Formatter('%(asctime)s - %(message)s')
cleanup_handler.setFormatter(cleanup_formatter)
cleanup_logger.addHandler(cleanup_handler)

# --------------------------- Función para limpiar registros antiguos ---------------------------
# --------------------------- Función para limpiar registros antiguos ---------------------------
def limpiar_mes_antiguo(destino_cursor, table_name):
    try:
        # Obtener el mes más antiguo
        query_mes_antiguo = f"""
            SELECT MIN(CONCAT(YEAR(calldate), '-', RIGHT('0' + CAST(MONTH(calldate) AS VARCHAR), 2))) AS mes_antiguo
            FROM {table_name};
        """
        destino_cursor.execute(query_mes_antiguo)
        mes_antiguo = destino_cursor.fetchone()[0]

        # Contar los meses distintos en la tabla
        query_contar_meses = f"""
            SELECT COUNT(DISTINCT CONCAT(YEAR(calldate), '-', RIGHT('0' + CAST(MONTH(calldate) AS VARCHAR), 2))) AS total_meses
            FROM {table_name};
        """
        destino_cursor.execute(query_contar_meses)
        total_meses = destino_cursor.fetchone()[0]

        # Si hay más de 3 meses, eliminar el mes más antiguo
        if total_meses > 3 and mes_antiguo:
            year, month = mes_antiguo.split('-')
            delete_query = f"""
                DELETE FROM {table_name}
                WHERE YEAR(calldate) = {year} AND MONTH(calldate) = {int(month)};
            """
            destino_cursor.execute(delete_query)
            destino_cursor.connection.commit()  # Confirmar cambios
            
            registros_eliminados = destino_cursor.rowcount
            mensaje = f"Registros del mes {mes_antiguo} eliminados exitosamente. Total eliminados: {registros_eliminados}."
            print(mensaje)
            cleanup_logger.info(mensaje)
        else:
            cleanup_logger.info("No se requiere limpieza de registros.")

    except Exception as e:
        cleanup_logger.error(f"Error en la limpieza de registros: {e}")

# --------------------------- Configuración de Conexiones ---------------------------
AZURE_SQL_SERVER, AZURE_SQL_DB, AZURE_SQL_USER, AZURE_SQL_PASSWORD = load_credentials()
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

# --------------------------- Sincronización de Nuevos Registros ---------------------------
def sincronizar_nuevos_registros():
    try:
        sync_logger.info("Iniciando sincronización de nuevos registros...")

        # Conexión a MySQL (Origen)
        origen_conn = mysql.connector.connect(
            host=socket.gethostname(), user=ORIGEN_USER, password=ORIGEN_PASSWORD, database=ORIGEN_DB
        )
        origen_cursor = origen_conn.cursor(dictionary=True)

        # Conexión a Azure SQL (Destino)
        destino_conn = pyodbc.connect(AZURE_SQL_CONNECTION_STRING)
        destino_cursor = destino_conn.cursor()

        TABLE_NAME = get_table_name()

        # Realizar limpieza de registros antiguos
        limpiar_mes_antiguo(destino_cursor, TABLE_NAME)

        # Obtener el calldate y uniqueid más reciente de Azure SQL
        query_max = f"""
            SELECT MAX(calldate) AS ultima_fecha, MAX(uniqueid) AS ultimo_uniqueid
            FROM {TABLE_NAME};
        """
        destino_cursor.execute(query_max)
        resultado = destino_cursor.fetchone()

        ultima_fecha = resultado[0] if resultado[0] else '1970-01-01 00:00:00'
        ultimo_uniqueid = resultado[1] if resultado[1] else ''

        # Consultar registros nuevos en MySQL
        query_nuevos = """
            SELECT * FROM cdr
            WHERE calldate > %s OR (calldate = %s AND uniqueid > %s)
            ORDER BY calldate, uniqueid;
        """
        origen_cursor.execute(query_nuevos, (ultima_fecha, ultima_fecha, ultimo_uniqueid))
        registros = origen_cursor.fetchall()

        if registros:
            mensaje = f"Última fecha sincronizada: {ultima_fecha} | Nuevos registros encontrados: {len(registros)}"
            print(mensaje)
            sync_logger.info(mensaje)

            insert_query = f"""
                INSERT INTO {TABLE_NAME} (
                    calldate, clid, src, dst, dcontext, channel, dstchannel, lastapp, lastdata, duration,
                    billsec, disposition, amaflags, accountcode, uniqueid, userfield, did, recordingfile,
                    cnum, cnam, outbound_cnum, outbound_cnam, dst_cnam, linkedid, peeraccount, sequence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            for idx, fila in enumerate(registros):
                destino_cursor.execute(insert_query, (
                    fila['calldate'], fila['clid'], fila['src'], fila['dst'], fila['dcontext'],
                    fila['channel'], fila['dstchannel'], fila['lastapp'], fila['lastdata'], fila['duration'],
                    fila['billsec'], fila['disposition'], fila['amaflags'], fila['accountcode'], fila['uniqueid'],
                    fila['userfield'], fila['did'], fila['recordingfile'], fila['cnum'], fila['cnam'],
                    fila['outbound_cnum'], fila['outbound_cnam'], fila['dst_cnam'], fila['linkedid'],
                    fila['peeraccount'], fila['sequence']
                ))
                sync_logger.info(f"Registro {idx + 1} sincronizado.")

            destino_conn.commit()
            sync_logger.info("Sincronización completada exitosamente.")
        else:
            mensaje = f"Última fecha sincronizada: {ultima_fecha} | No hay nuevos registros para sincronizar."
            print(mensaje)
            sync_logger.info(mensaje)

    except Exception as e:
        sync_logger.error(f"Error en la sincronización: {e}")
    finally:
        if 'origen_cursor' in locals(): origen_cursor.close()
        if 'origen_conn' in locals(): origen_conn.close()
        if 'destino_cursor' in locals(): destino_cursor.close()
        if 'destino_conn' in locals(): destino_conn.close()

# --------------------------- Ejecución Principal ---------------------------
if __name__ == "__main__":
    sincronizar_nuevos_registros()
