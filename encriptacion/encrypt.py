from cryptography.fernet import Fernet

# Generar una clave y guardarla en un archivo
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    print("Clave generada y guardada en 'secret.key'.")

# Cifrar un mensaje con la clave
def encrypt_data(data, key_file="secret.key"):
    with open(key_file, "rb") as file:
        key = file.read()
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    return encrypted_data

if __name__ == "__main__":
    # Generar la clave (solo la primera vez)
    generate_key()

    # Datos sensibles a cifrar
    azure_server = "sqlfs.database.windows.net"
    azure_db = "sql_free"
    azure_user = "sqlreportes"
    azure_password = "6dg3Pt32"

    # Cifrar los datos
    print("Cifrando datos...")
    encrypted_server = encrypt_data(azure_server)
    encrypted_db = encrypt_data(azure_db)
    encrypted_user = encrypt_data(azure_user)
    encrypted_password = encrypt_data(azure_password)

    # Guardar los datos cifrados en un archivo
    with open("encrypted_credentials.txt", "wb") as file:
        file.write(encrypted_server + b"\n")
        file.write(encrypted_db + b"\n")
        file.write(encrypted_user + b"\n")
        file.write(encrypted_password + b"\n")

    print("Datos cifrados y guardados en 'encrypted_credentials.txt'.")
