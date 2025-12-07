# ===============================================================
# CHATWITHBACKDOOR - SERVIDOR (BACKDOOR + HMAC + BLOB + DB + USERS)
# ===============================================================
# Funcionalidades:
#   - Registo de utilizadores com:
#       username, password (hash+salt), chave publica RSA (DER base64)
#   - Autenticacao forte:
#       1) LOGIN <username> <password>
#       2) Servidor responde com NONCE <b64>
#       3) Cliente envia LOGIN_SIG <username> <signature_base64>
#          (assinatura digital do nonce com RSA-PSS)
#   - Diretoria de chaves publicas: GET_PK
#   - DH efémero + encaminhamento de mensagens cifradas (MSG) com backdoor
#   - Encaminhamento de mensagens em claro (TO) [debug]
#   - Base de dados SQLite (chat.db):
#       Tabela users:
#         username, password_hash, salt, pubkey_b64
#       Tabela messages:
#         sender, recipient, ts_unix,
#         header_b64, blob_b64, iv_b64, cipher_b64, tag_b64
#   - HISTORY dest [-d YYYY-MM-DD|--date YYYY-MM-DD] [-c N|--count N]
#       usa backdoor para decifrar histórico da BD
#
#   Backdoor (versao com blob, alinhada com o enunciado/diagrama):
#       blob   = AES-ECB_Encrypt(K_SERVER, K_enc)
#       IV     = primeiros 16 bytes de blob   (como K_enc tem 16 bytes, blob == IV)
#       K_enc  = AES-ECB_Decrypt(K_SERVER, blob)
#       K_mac  = SHA256(K_enc)
#       tag    = HMAC_SHA256(K_mac, header || blob || IV || C)
# ===============================================================

import socket
import threading
import base64
import os
import hashlib
import hmac
import sqlite3
import time
from datetime import datetime, timedelta

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympadding

HOST = "127.0.0.1"
PORT = 5000

# Chave secreta do servidor para a backdoor (AES-128)
K_SERVER = b"0123456789abcdef"  # 16 bytes

# Utilizadores registados em memoria: username -> public_key (objeto cryptography)
# (chave SEMPRE normalizada para lowercase)
users = {}

# Clientes online e autenticados: username -> socket
# (chave SEMPRE normalizada para lowercase)
online_clients = {}

# Lock global para proteger estruturas partilhadas (users, online_clients, pending_nonces)
lock = threading.Lock()

# Nonces de login pendentes: conn -> (username_normalizado, nonce_bytes)
pending_nonces = {}

# Base de dados para guardar mensagens cifradas e utilizadores
db_conn = None
db_lock = threading.Lock()


# ---------------------------------------------------
# NORMALIZACAO DE USERNAMES 
# ---------------------------------------------------
# O servidor passa a tratar todos os usernames de forma case-insensitive.
# Por exemplo, "Alice", "alice" e "ALICE" são sempre o mesmo utilizador.
# Tudo é guardado e consultado em lowercase.
def norm_username(u: str) -> str:
    """Normaliza usernames para ser tudo case-insensitive."""
    return u.strip().lower()


# ---------------------------------------------------
# AUXILIARES CRIPTO (AES + HMAC)
# ---------------------------------------------------
def aes_encrypt_ecb(key: bytes, block: bytes) -> bytes:
    """
    Cifra o bloco no input com AES-ECB.
    
    Input: key (16 bytes), block (16 bytes)
    Output: ciphertext (16 bytes)
    """
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(block) + enc.finalize()


def aes_decrypt_ecb(key: bytes, block: bytes) -> bytes:
    """
    Decifra o bloco no com AES-ECB.
    
    Input: key (16 bytes), block (16 bytes)
    Output: plaintext (16 bytes)
    
    Usado para recuperar K_enc a partir do blob (backdoor).
    """
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    dec = cipher.decryptor()
    return dec.update(block) + dec.finalize()


def aes_encrypt_cbc(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """
    Cifra os dados recebidos com AES-CBC e padding PKCS7.
    
    Input: key (16 bytes), iv (16 bytes), plaintext (bytes)
    Output: ciphertext (bytes)
    
    Usado para recifrar mensagens modificadas.
    """
    padder = sympadding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def aes_decrypt_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decifra os dados recebidos com AES-CBC e remove o padding PKCS7.
    
    Input: key (16 bytes), iv (16 bytes), ciphertext (bytes)
    Output: plaintext (bytes)
    
    Esta função é usada no backdoor para ler as mensagens dos clientes.
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = sympadding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """
    Calcula HMAC-SHA256.
    
    Input: key (bytes), data (bytes)
    Output: tag (32 bytes)
    """
    # HMAC usado para garantir integridade (não-confundível) das mensagens
    return hmac.new(key, data, hashlib.sha256).digest()


# ---------------------------------------------------
# PASSWORDS (hash + salt)
# ---------------------------------------------------
def hash_password(password: str, salt: bytes) -> str:
    """
    Hash simples de password com salt:
      hash = SHA256(salt || password)
    Guardado em hex na BD.
    """
    pw_bytes = password.encode("utf-8")
    return hashlib.sha256(salt + pw_bytes).hexdigest()


# ---------------------------------------------------
# RSA
# ---------------------------------------------------
def load_public_key_from_der(der_bytes: bytes):
    # Converte bytes DER numa chave publica RSA (objeto cryptography)
    return serialization.load_der_public_key(der_bytes)


def verify_signature(pubkey, nonce: bytes, signature: bytes) -> bool:
    """
    Verifica a assinatura RSA-PSS de um nonce.
    
    Input:
      - pubkey: RSAPublicKey
      - nonce: bytes (dados assinados)
      - signature: bytes (assinatura)
    
    Output: bool (True se válida)
    """
    try:
        pubkey.verify(
            signature,
            nonce,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# ---------------------------------------------------
# BASE DE DADOS (SQLite)
# ---------------------------------------------------
def init_db(db_path: str = "chat.db"):
    """
    Inicializa a base de dados SQLite (se nao existir, cria).
    Guarda utilizadores e mensagens cifradas.
    """
    global db_conn
    db_conn = sqlite3.connect(db_path, check_same_thread=False)
    cur = db_conn.cursor()

    # Tabela de utilizadores (username, hash da password, salt e chave publica)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    NOT NULL UNIQUE,
            password_hash TEXT    NOT NULL,
            salt          BLOB    NOT NULL,
            pubkey_b64    TEXT    NOT NULL
        );
        """
    )

    # Tabela de mensagens cifradas (tudo guardado em base64, mais timestamp)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender      TEXT    NOT NULL,
            recipient   TEXT    NOT NULL,
            ts_unix     INTEGER NOT NULL,
            header_b64  TEXT    NOT NULL,
            blob_b64    TEXT    NOT NULL,
            iv_b64      TEXT    NOT NULL,
            cipher_b64  TEXT    NOT NULL,
            tag_b64     TEXT    NOT NULL
        );
        """
    )

    db_conn.commit()
    load_users_from_db()


def load_users_from_db():
    """
    Carrega utilizadores da tabela users para o dicionario 'users'
    (apenas as chaves publicas). Chave SEMPRE normalizada.
    """
    if db_conn is None:
        return

    with db_lock:
        cur = db_conn.cursor()
        cur.execute("SELECT username, pubkey_b64 FROM users")
        rows = cur.fetchall()

    with lock:
        for username_db, pubkey_b64 in rows:
            try:
                der = base64.b64decode(pubkey_b64.encode("utf-8"), validate=True)
                pk_obj = load_public_key_from_der(der)
                # normalizar username vindo da BD
                username_norm = norm_username(username_db)
                users[username_norm] = pk_obj
            except Exception as e:
                print(f"[ERRO] Falha ao carregar chave de {username_db} da BD: {e}")


def store_encrypted_message(
    sender: str,
    recipient: str,
    header_b64: str,
    blob_b64: str,
    iv_b64: str,
    cipher_b64: str,
    tag_b64: str,
):
    """
    Guarda uma mensagem cifrada na base de dados.
    """
    if db_conn is None:
        return  # DB nao inicializada

    ts = int(time.time())
    sender_norm = norm_username(sender)
    recipient_norm = norm_username(recipient)

    with db_lock:
        cur = db_conn.cursor()
        cur.execute(
            """
            INSERT INTO messages (
                sender, recipient, ts_unix,
                header_b64, blob_b64, iv_b64, cipher_b64, tag_b64
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (sender_norm, recipient_norm, ts, header_b64, blob_b64, iv_b64, cipher_b64, tag_b64),
        )
        db_conn.commit()


def fetch_history(
    user1: str,
    user2: str,
    date_str: str | None = None,
    limit: int = 50,
):
    """
    Vai buscar as ultimas 'limit' mensagens entre user1 e user2 (case-insensitive).
    Se date_str for fornecido (YYYY-MM-DD), filtra por esse dia.
    Devolve lista ordenada cronologicamente (do mais antigo para o mais recente).
    """
    if db_conn is None:
        return []

    u1 = norm_username(user1)
    u2 = norm_username(user2)

    # Comparacao case-insensitive usando LOWER() na BD
    params = [u1, u2, u2, u1]
    where = (
        "WHERE (LOWER(sender) = ? AND LOWER(recipient) = ?) "
        "OR (LOWER(sender) = ? AND LOWER(recipient) = ?)"
    )

    if date_str:
        # Filtrar por um dia específico (meia-noite até meia-noite seguinte)
        try:
            dt_day = datetime.strptime(date_str, "%Y-%m-%d")
        except ValueError:
            return None  # sinal de data invalida
        start_ts = int(dt_day.timestamp())
        end_ts = int((dt_day + timedelta(days=1)).timestamp())
        where += " AND ts_unix >= ? AND ts_unix < ?"
        params.extend([start_ts, end_ts])

    sql = (
        "SELECT sender, recipient, ts_unix, header_b64, blob_b64, iv_b64, cipher_b64, tag_b64 "
        "FROM messages "
        f"{where} "
        "ORDER BY ts_unix DESC "
        "LIMIT ?"
    )
    params.append(limit)

    with db_lock:
        cur = db_conn.cursor()
        cur.execute(sql, tuple(params))
        rows = cur.fetchall()

    # rows vem do mais recente para o mais antigo -> inverter para mostrar em ordem crescente
    rows.reverse()
    return rows


def fetch_user_record(username: str):
    """
    Vai buscar (password_hash, salt, pubkey_b64) de um utilizador (case-insensitive),
    ou None se nao existir.
    """
    if db_conn is None:
        return None

    username_norm = norm_username(username)

    with db_lock:
        cur = db_conn.cursor()
        # Comparacao case-insensitive no campo username
        cur.execute(
            "SELECT password_hash, salt, pubkey_b64 FROM users WHERE LOWER(username) = ?",
            (username_norm,),
        )
        row = cur.fetchone()
    return row


def create_user(username: str, password: str, pubkey_b64: str):
    """
    Cria utilizador na BD com password hash + salt e pubkey_b64.
    Levanta sqlite3.IntegrityError se username ja existir (UNIQUE).
    username é guardado normalizado (lowercase).
    """
    if db_conn is None:
        raise RuntimeError("BD nao inicializada")

    username_norm = norm_username(username)

    salt = os.urandom(16)
    pwd_hash = hash_password(password, salt)

    with db_lock:
        cur = db_conn.cursor()
        cur.execute(
            """
            INSERT INTO users (username, password_hash, salt, pubkey_b64)
            VALUES (?, ?, ?, ?)
            """,
            (username_norm, pwd_hash, salt, pubkey_b64),
        )
        db_conn.commit()


def verify_user_password(username: str, password: str) -> bool:
    """
    Verifica se username existe e se a password corresponde ao hash guardado.
    (case-insensitive)
    """
    row = fetch_user_record(username)
    if row is None:
        return False

    stored_hash, salt, _ = row
    calc_hash = hash_password(password, salt)
    return hmac.compare_digest(stored_hash, calc_hash)


# ---------------------------------------------------
# FUNCOES AUXILIARES
# ---------------------------------------------------
def broadcast_system_message(msg: str):
    """
    Envia uma mensagem de sistema para todos os clientes autenticados.
    
    Input: msg (str)
    Output: None
    """
    with lock:
        for sock in online_clients.values():
            try:
                sock.sendall(f"[SERVIDOR] {msg}\n".encode("utf-8"))
            except Exception:
                # Se falhar com algum cliente, ignoramos e continuamos
                pass


# ---------------------------------------------------
# THREAD POR CLIENTE
# ---------------------------------------------------
def handle_client(conn: socket.socket, addr):
    """
    Thread principal para gestão de um cliente.
    
    Input: conn (socket), addr (endereço)
    Output: None
    
    Processa os comandos:
      - REGISTER: registo de utilizador
      - LOGIN / LOGIN_SIG: autenticação
      - GET_PK: obter chave pública de utilizador
      - DH_INIT / DH_REPLY: encaminhar trocas DH
      - TO: mensagem em claro
      - MSG: mensagem cifrada (com backdoor)
      - LIST: listar utilizadores online
      - QUIT: desconectar
    """
    print(f"[DEBUG] Ligacao de {addr}")
    current_username = None  # SEMPRE normalizado
    authenticated = False

    try:
        conn.sendall(b"OK Ligado ao ChatWithBackdoor v4.0. Use REGISTER ou LOGIN.\n")

        while True:
            data = conn.recv(4096)
            if not data:
                break

            line = data.decode("utf-8", errors="ignore").strip()
            if not line:
                continue

            # ---------------------------------------------------
            # 1) REGISTO
            #     REGISTER <username> <password> <pubkey_der_base64>
            # ---------------------------------------------------
            if line.startswith("REGISTER "):
                parts = line.split(" ", 3)
                if len(parts) < 4:
                    conn.sendall(
                        b"ERR Uso: REGISTER <username> <password> <pubkey_der_base64>\n"
                    )
                    continue
                _, username_raw, password_raw, b64_pk = parts
                username = norm_username(username_raw)
                password = password_raw.strip()

                if not username:
                    conn.sendall(b"ERR Username vazio\n")
                    continue
                if not password:
                    conn.sendall(b"ERR Password vazia\n")
                    continue

                # Verificar se username ja existe na BD 
                if fetch_user_record(username) is not None:
                    conn.sendall(b"ERR Username ja registado\n")
                    continue

                # Validar chave publica recebida do cliente
                try:
                    der_bytes = base64.b64decode(b64_pk.encode("utf-8"), validate=True)
                    pubkey = load_public_key_from_der(der_bytes)
                except Exception:
                    conn.sendall(b"ERR Chave publica invalida (base64/DER)\n")
                    continue

                # Criar utilizador na BD (password hash + salt + pubkey_b64)
                try:
                    create_user(username, password, b64_pk)
                except sqlite3.IntegrityError:
                    conn.sendall(b"ERR Username ja registado\n")
                    continue
                except Exception as e:
                    print(f"[ERRO] Ao criar utilizador na BD: {e}")
                    conn.sendall(b"ERR Erro interno ao registar utilizador\n")
                    continue

                # Atualizar dicionario em memoria
                with lock:
                    users[username] = pubkey  

                conn.sendall(b"OK REGISTER\n")
                continue

            # ---------------------------------------------------
            # 2) LOGIN - PASSWORD + NONCE
            #     LOGIN <username> <password>
            # ---------------------------------------------------
            if line.startswith("LOGIN "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    conn.sendall(b"ERR Uso: LOGIN <username> <password>\n")
                    continue
                _, username_raw, password_raw = parts
                username = norm_username(username_raw)
                password = password_raw.strip()

                if not username or not password:
                    conn.sendall(b"ERR Username ou password vazios\n")
                    continue

                # 1) Verificar password na BD 
                if not verify_user_password(username, password):
                    conn.sendall(b"ERR Username ou password invalida\n")
                    continue

                # 2) Garantir que temos chave publica em memoria
                with lock:
                    pk_obj = users.get(username)

                if pk_obj is None:
                    # Se ainda nao estiver em memoria, recarregamos da BD
                    row = fetch_user_record(username)
                    if row is None:
                        conn.sendall(
                            b"ERR Erro interno (utilizador sem registo completo na BD)\n"
                        )
                        continue
                    _, _, pubkey_b64 = row
                    try:
                        der_bytes = base64.b64decode(
                            pubkey_b64.encode("utf-8"), validate=True
                        )
                        pk_obj = load_public_key_from_der(der_bytes)
                        with lock:
                            users[username] = pk_obj
                    except Exception:
                        conn.sendall(
                            b"ERR Erro interno ao carregar chave publica do utilizador\n"
                        )
                        continue

                # 3) Password OK -> gerar NONCE (2.ª fase do LOGIN)
                nonce = os.urandom(32)
                b64_nonce = base64.b64encode(nonce).decode("utf-8")

                with lock:
                    # Associar nonce ao username normalizado
                    pending_nonces[conn] = (username, nonce)

                conn.sendall(f"NONCE {b64_nonce}\n".encode("utf-8"))
                continue

            # ---------------------------------------------------
            # 3) LOGIN_SIG - ASSINATURA DO NONCE
            #     LOGIN_SIG <username> <signature_base64>
            # ---------------------------------------------------
            if line.startswith("LOGIN_SIG "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    conn.sendall(b"ERR Uso: LOGIN_SIG <username> <signature_base64>\n")
                    continue
                _, username_raw, b64_sig = parts
                username = norm_username(username_raw)

                try:
                    signature = base64.b64decode(b64_sig.encode("utf-8"), validate=True)
                except Exception:
                    conn.sendall(b"ERR Signature nao e base64 valida\n")
                    continue

                with lock:
                    pending = pending_nonces.get(conn)

                if pending is None:
                    conn.sendall(b"ERR Nao ha nonce de login pendente para esta ligacao\n")
                    continue

                nonce_username, nonce = pending

                # Proteger contra troca de username entre LOGIN e LOGIN_SIG
                if nonce_username != username:
                    conn.sendall(b"ERR Username nao corresponde ao nonce pendente\n")
                    continue

                with lock:
                    pubkey = users.get(username)

                if pubkey is None:
                    conn.sendall(b"ERR Username nao registado\n")
                    continue

                ok = verify_signature(pubkey, nonce, signature)
                if not ok:
                    conn.sendall(b"ERR LOGIN assinatura invalida\n")
                    continue

                authenticated = True
                current_username = username  # normalizado

                with lock:
                    pending_nonces.pop(conn, None)
                    online_clients[current_username] = conn  # chave normalizada

                conn.sendall(b"OK LOGIN\n")
                broadcast_system_message(f"{current_username} autenticou-se e entrou no chat.")
                continue

            # ---------------------------------------------------
            # A partir daqui, so autenticado
            # ---------------------------------------------------
            if not authenticated:
                conn.sendall(b"ERR Precisa de fazer LOGIN primeiro\n")
                continue

            # ---------------------------------------------------
            # 4) GET_PK <username>
            #     devolve a chave publica RSA de outro utilizador
            # ---------------------------------------------------
            if line.startswith("GET_PK "):
                parts = line.split(" ", 1)
                if len(parts) < 2:
                    conn.sendall(b"ERR Uso: GET_PK <username>\n")
                    continue
                _, target_user_raw = parts
                target_user = norm_username(target_user_raw)

                with lock:
                    pk_obj = users.get(target_user)

                if pk_obj is None:
                    conn.sendall(b"ERR Username nao registado\n")
                    continue

                try:
                    der_bytes = pk_obj.public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    b64_pk = base64.b64encode(der_bytes).decode("utf-8")
                except Exception:
                    conn.sendall(b"ERR Falha ao serializar chave publica\n")
                    continue

                conn.sendall(f"PK {target_user} {b64_pk}\n".encode("utf-8"))
                continue

            # ---------------------------------------------------
            # 5) DH_INIT: encaminhar chave DH efemera
            # ---------------------------------------------------
            if line.startswith("DH_INIT "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    conn.sendall(b"ERR Uso: DH_INIT <dest> <b64_dh_pub>\n")
                    continue
                _, dest_raw, b64_dh_pub = parts
                dest = norm_username(dest_raw)

                with lock:
                    dest_sock = online_clients.get(dest)

                if dest_sock is None:
                    conn.sendall(f"ERR Utilizador '{dest}' nao esta online\n".encode("utf-8"))
                    continue

                out = f"DH_INIT_FROM {current_username} {b64_dh_pub}\n".encode("utf-8")
                try:
                    dest_sock.sendall(out)
                except Exception:
                    conn.sendall(f"ERR Falha ao enviar DH_INIT para {dest}\n".encode("utf-8"))
                continue

            # ---------------------------------------------------
            # 6) DH_REPLY: encaminhar resposta DH
            # ---------------------------------------------------
            if line.startswith("DH_REPLY "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    conn.sendall(b"ERR Uso: DH_REPLY <dest> <b64_dh_pub>\n")
                    continue
                _, dest_raw, b64_dh_pub = parts
                dest = norm_username(dest_raw)

                with lock:
                    dest_sock = online_clients.get(dest)

                if dest_sock is None:
                    conn.sendall(f"ERR Utilizador '{dest}' nao esta online\n".encode("utf-8"))
                    continue

                out = f"DH_REPLY_FROM {current_username} {b64_dh_pub}\n".encode("utf-8")
                try:
                    dest_sock.sendall(out)
                except Exception:
                    conn.sendall(f"ERR Falha ao enviar DH_REPLY para {dest}\n".encode("utf-8"))
                continue

            # ---------------------------------------------------
            # 7) LIST
            # ---------------------------------------------------
            if line == "LIST":
                with lock:
                    names = ", ".join(sorted(online_clients.keys()))
                conn.sendall(f"USERS {names}\n".encode("utf-8"))
                continue

            # ---------------------------------------------------
            # 8) HISTORY dest [opções]
            #     HISTORY <user> [-d YYYY-MM-DD|--date YYYY-MM-DD] [-c N|--count N]
            #     Usa a backdoor para ler mensagens cifradas da BD.
            # ---------------------------------------------------
            if line.startswith("HISTORY "):
                tokens = line.split()
                if len(tokens) < 2:
                    conn.sendall(
                        b"ERR Uso: HISTORY <user> [-d YYYY-MM-DD|--date YYYY-MM-DD] [-c N|--count N]\n"
                    )
                    continue

                peer_raw = tokens[1]
                peer = norm_username(peer_raw)
                date_filter = None
                limit = 50

                # Parsing das flags opcionais (-d / -c)
                i = 2
                while i < len(tokens):
                    flag = tokens[i]
                    if flag in ("-d", "--date"):
                        if i + 1 >= len(tokens):
                            conn.sendall(b"ERR Falta data apos -d/--date\n")
                            break
                        date_filter = tokens[i + 1]
                        i += 2
                    elif flag in ("-c", "--count"):
                        if i + 1 >= len(tokens):
                            conn.sendall(b"ERR Falta numero apos -c/--count\n")
                            break
                        try:
                            limit = int(tokens[i + 1])
                            if limit <= 0:
                                limit = 50
                        except ValueError:
                            conn.sendall(b"ERR Valor invalido para -c/--count\n")
                            break
                        i += 2
                    else:
                        conn.sendall(f"ERR Flag desconhecida em HISTORY: {flag}\n".encode("utf-8"))
                        break
                else:
                    # só entra aqui se nao foi feito "break" no while
                    rows = fetch_history(current_username, peer, date_filter, limit)
                    if rows is None:
                        conn.sendall(b"ERR Data invalida (usa YYYY-MM-DD)\n")
                        continue

                    if not rows:
                        conn.sendall(
                            f"[HISTORY] Nao ha mensagens entre {current_username} e {peer}.\n".encode(
                                "utf-8"
                            )
                        )
                        continue

                    header_msg = (
                        f"[HISTORY] Historico entre {current_username} e {peer}"
                        f" (max {limit} mensagens"
                    )
                    if date_filter:
                        header_msg += f", dia {date_filter}"
                    header_msg += "):\n"
                    conn.sendall(header_msg.encode("utf-8"))

                    # Para cada linha, o servidor usa a backdoor para decifrar
                    # e mostrar o texto original ao utilizador que pediu o histórico.
                    for (
                        sender,
                        recipient,
                        ts_unix,
                        header_b64,
                        blob_b64,
                        iv_b64,
                        cipher_b64,
                        tag_b64,
                    ) in rows:
                        try:
                            header = base64.b64decode(
                                header_b64.encode("utf-8"), validate=True
                            )
                            blob = base64.b64decode(blob_b64.encode("utf-8"), validate=True)
                            iv = base64.b64decode(iv_b64.encode("utf-8"), validate=True)
                            cipher = base64.b64decode(
                                cipher_b64.encode("utf-8"), validate=True
                            )
                            tag = base64.b64decode(tag_b64.encode("utf-8"), validate=True)
                        except Exception:
                            msg_line = f"[HISTORY] {sender}->{recipient} [ERRO base64]\n"
                            conn.sendall(msg_line.encode("utf-8", errors="ignore"))
                            continue

                        # Recuperar K_enc / K_mac via backdoor (AES-ECB com K_SERVER)
                        try:
                            k_enc = aes_decrypt_ecb(K_SERVER, blob)
                            k_mac = hashlib.sha256(k_enc).digest()
                        except Exception:
                            msg_line = f"[HISTORY] {sender}->{recipient} [ERRO backdoor]\n"
                            conn.sendall(msg_line.encode("utf-8", errors="ignore"))
                            continue

                        # Verificar HMAC antes de decifrar
                        calc_tag = hmac_sha256(k_mac, header + blob + iv + cipher)
                        if not hmac.compare_digest(calc_tag, tag):
                            msg_line = f"[HISTORY] {sender}->{recipient} [HMAC INVALIDO]\n"
                            conn.sendall(msg_line.encode("utf-8", errors="ignore"))
                            continue

                        # Decifrar texto da mensagem guardada na BD
                        try:
                            plaintext = aes_decrypt_cbc(k_enc, iv, cipher)
                            plaintext_str = plaintext.decode("utf-8", errors="replace")
                        except Exception:
                            plaintext_str = "[ERRO AO DECIFRAR]"

                        dt_str = datetime.fromtimestamp(ts_unix).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                        msg_line = (
                            f"[{dt_str}] {sender} -> {recipient}: {plaintext_str}\n"
                        )
                        conn.sendall(msg_line.encode("utf-8", errors="ignore"))

                continue

            # ---------------------------------------------------
            # 9) TO <dest> <mensagem>  (modo antigo, em claro)
            # ---------------------------------------------------
            if line.startswith("TO "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    conn.sendall(b"ERR Uso: TO <dest> <mensagem>\n")
                    continue

                _, dest_raw, msg = parts
                dest = norm_username(dest_raw)

                with lock:
                    dest_sock = online_clients.get(dest)

                if dest_sock is None:
                    conn.sendall(f"ERR Utilizador '{dest}' nao esta online\n".encode("utf-8"))
                    continue

                out = f"FROM {current_username}: {msg}\n".encode("utf-8")
                try:
                    dest_sock.sendall(out)
                except Exception:
                    conn.sendall(b"ERR Falha ao enviar para {dest}\n".encode("utf-8"))
                continue

            # ---------------------------------------------------
            # 10) MSG <dest> <b64_header> <b64_blob> <b64_iv> <b64_cipher> <b64_tag>
            #     -> servidor usa backdoor para ler/alterar e guarda na BD
            # ---------------------------------------------------
            if line.startswith("MSG "):
                parts = line.split(" ", 6)
                if len(parts) < 7:
                    conn.sendall(
                        b"ERR Uso: MSG <dest> <b64_header> <b64_blob> <b64_iv> <b64_cipher> <b64_tag>\n"
                    )
                    continue

                _, dest_raw, b64_header, b64_blob, b64_iv, b64_cipher, b64_tag = parts
                dest = norm_username(dest_raw)

                with lock:
                    dest_sock = online_clients.get(dest)

                if dest_sock is None:
                    conn.sendall(f"ERR Utilizador '{dest}' nao esta online\n".encode("utf-8"))
                    continue

                try:
                    header = base64.b64decode(b64_header.encode("utf-8"), validate=True)
                    blob = base64.b64decode(b64_blob.encode("utf-8"), validate=True)
                    iv = base64.b64decode(b64_iv.encode("utf-8"), validate=True)
                    cipher = base64.b64decode(b64_cipher.encode("utf-8"), validate=True)
                    tag = base64.b64decode(b64_tag.encode("utf-8"), validate=True)
                except Exception:
                    conn.sendall(b"ERR MSG campos base64 invalidos\n")
                    continue

                # 1) Recuperar K_enc a partir do blob (backdoor)
                try:
                    k_enc = aes_decrypt_ecb(K_SERVER, blob)
                except Exception:
                    conn.sendall(b"ERR Falha ao recuperar K_enc a partir do blob\n")
                    continue

                # 2) Derivar K_mac
                k_mac = hashlib.sha256(k_enc).digest()

                # 3) Verificar HMAC (garante integridade da mensagem)
                calc_tag = hmac_sha256(k_mac, header + blob + iv + cipher)
                if not hmac.compare_digest(calc_tag, tag):
                    conn.sendall(b"ERR HMAC invalido (mensagem corrompida)\n")
                    continue

                # 4) Decifrar mensagem (texto original enviado pelo cliente)
                try:
                    plaintext = aes_decrypt_cbc(k_enc, iv, cipher)
                except Exception:
                    conn.sendall(b"ERR Falha ao decifrar mensagem\n")
                    continue

                try:
                    plaintext_str = plaintext.decode("utf-8")
                except Exception:
                    plaintext_str = plaintext.decode("utf-8", errors="replace")

                # 5) Mostrar no servidor (backdoor: o servidor consegue ler tudo)
                print(f"[BACKDOOR] {current_username} -> {dest}: {plaintext_str}")

                # 6) Opcional: alterar mensagem (exemplo simples com comando !upper)
                msg_mod = plaintext_str
                if msg_mod.startswith("!upper "):
                    msg_mod = msg_mod[len("!upper ") :].upper()

                plaintext_out = msg_mod.encode("utf-8")

                # 7) Recifrar / recalcular HMAC com o mesmo K_enc/K_mac
                cipher_out = aes_encrypt_cbc(k_enc, iv, plaintext_out)
                tag_out = hmac_sha256(k_mac, header + blob + iv + cipher_out)

                b64_cipher_out = base64.b64encode(cipher_out).decode("utf-8")
                b64_tag_out = base64.b64encode(tag_out).decode("utf-8")

                # 7.5) Guardar na base de dados a mensagem CIFRADA final
                store_encrypted_message(
                    sender=current_username,
                    recipient=dest,
                    header_b64=b64_header,
                    blob_b64=b64_blob,
                    iv_b64=b64_iv,
                    cipher_b64=b64_cipher_out,
                    tag_b64=b64_tag_out,
                )

                # 8) Enviar ao destinatario (formato MSG_FROM ...)
                wire = (
                    f"MSG_FROM {current_username} "
                    f"{b64_header} {b64_blob} {b64_iv} {b64_cipher_out} {b64_tag_out}\n"
                )
                try:
                    dest_sock.sendall(wire.encode("utf-8"))
                except Exception:
                    conn.sendall(f"ERR Falha ao enviar MSG para {dest}\n".encode("utf-8"))
                continue

            # ---------------------------------------------------
            # 11) QUIT
            # ---------------------------------------------------
            if line == "QUIT":
                conn.sendall(b"OK Adeus\n")
                break

            # ---------------------------------------------------
            # 12) Comando desconhecido
            # ---------------------------------------------------
            conn.sendall(b"ERR Comando desconhecido\n")

    except Exception as e:
        print(f"[ERRO] Excecao com {addr}: {e}")

    finally:
        # Limpar estado do utilizador quando a ligação termina
        with lock:
            pending_nonces.pop(conn, None)
            if current_username and online_clients.get(current_username) is conn:
                del online_clients[current_username]

        if current_username:
            broadcast_system_message(f"{current_username} saiu do chat.")

        conn.close()
        print(f"[DEBUG] Ligacao terminada com {addr}")


def main():
    print(f"[INFO] Servidor a escutar em {HOST}:{PORT}")

    # Inicializar base de dados (cria ficheiro chat.db se nao existir)
    init_db("chat.db")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((HOST, PORT))
        server_sock.listen()

        # Ciclo principal: aceitar novas ligacoes e criar uma thread por cliente
        while True:
            conn, addr = server_sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()


if __name__ == "__main__":
    main()


"""
Terminal 1:
$ python3 server.py 
[INFO] Servidor a escutar em 127.0.0.1:5000
[DEBUG] Ligacao de ('127.0.0.1', 49860)
[DEBUG] Ligacao de ('127.0.0.1', 55480)
[BACKDOOR] Alice -> Bob: mensagem cifrada sem assinatura
[BACKDOOR] Alice -> Bob: mensagem assinada pela Alice||SIG||fFdyNWRrkTJ9mHLgKsGIrB/mq2BCMsDkFAwwT03hLgrRN68W5jECGYT8m0nnxnaQPAVQU/Lg8SVmM0nTaoAU3li8QPSHaUoRMYCnqzEcYqa9FZ79LfFjGGz01TbaLA48baYKysO9jX6w1XRrkQ0si1761v/7e8D7x6FX62SSnkVSiSL8lkDbF44zPp4H20+X7h/eu7YFl0m4H6RgPGN8iMeXky4g5v8PEH6+DQtZcSQPvU2OYXmH4OPakxkeJCZKhIGbSwx21Gg/eK24WFD5CSe/PmQw605MOQHS3QJHlQQpC5c3LcTCqR/5CQcr911S8UKMS3hx7io5cFYpF43Xww==
[BACKDOOR] Alice -> Bob: outra mensagem assinada pela Alice||SIG||UJVBCnorvmgsNgcZKXglWtEBhFiu50YVKOkLs56046TmrsVksJ+rNayL+B6fFACLZEh+V8+MB6Q0N79kTvI9aQZB9wO4Z8J/h8kwGQFea+9vk15V6LobdFLvk319/DRL1wSeVYCglxWUiT8L3xBey/gH5T9GpzMZPCVh1lOFGuYhqWFay9hGcwfSkDtfpoGnBLEdMxEyYN1THae4fiVoOvfzMECrkBL3TGNLIrAPEZRMt5V0cXKNNyPlKQj+sVPNGYmaZmJTDl4EidgQT9o+7grjO+bi3A12tb9ikYtrghgh9x4R9HEeRTFZYgXCHBT5coSiWRkREznP8sBqSLygOw==
[BACKDOOR] Alice -> Bob: !upper esta mensagem vai ser modificada
[DEBUG] Ligacao terminada com ('127.0.0.1', 49860)
[DEBUG] Ligacao terminada com ('127.0.0.1', 55480)


Terminal 2:
$ python3 client.py 
[INFO] A ligar ao servidor em 127.0.0.1:5000...
OK Ligado ao ChatWithBackdoor v3.1. Use REGISTER ou LOGIN.
Escolhe um username (identidade local): Alice
[INFO] A usar chaves existentes: Alice_priv.pem, Alice_pub.pem
Comandos (antes do LOGIN):
  /register  -> registar username + chave publica no servidor
  /login     -> autenticar com assinatura de nonce
  /quit      -> sair
-----------------------------------------------------
> /register
OK REGISTER
> /login
NONCE bhcs3C+MAqCI+EA6RhmLIACA2UFjwBCHTqCVBCQ4QF4=
OK LOGIN
[SERVIDOR] Alice autenticou-se e entrou no chat.
-----------------------------------------------------
[INFO] Autenticado! Agora podes usar o chat, DH e mensagens cifradas.
Comandos (chat + DH):
  /send <dest> <mensagem>       -> enviar mensagem CIFRADA (AES-CBC + HMAC + backdoor)
  /send_signed <dest> <mensagem>-> enviar mensagem CIFRADA + ASSINADA digitalmente
  /list                         -> listar utilizadores online
  /getpk <user>                 -> pedir chave publica RSA de <user> (para verificar assinaturas)
  /dh_start <user>              -> iniciar DH efemero com <user>
  /dh_show                      -> mostrar sessoes DH e chaves derivadas
  /quit                         -> sair
-----------------------------------------------------
> [SERVIDOR] Bob autenticou-se e entrou no chat.

> /list
> USERS Alice, Bob

> /to Bob mensagem em plaintext, sem ser cifrada
[MSG] Mensagem EM CLARO enviada para Bob.

> /dh_start Bob
[DH] Iniciado DH com Bob. A aguardar DH_REPLY_FROM Bob...
> [DH] Sessao DH com Bob COMPLETA (lado iniciador).
[DH]   Z (primeiros 16 hex): d1c34aa3f0925ac33c88bcf70c96b88d
[DH]   K_enc (primeiros 16 hex): 86b4176ad61dfcc56b51a8a23b8c0af8
[DH]   K_mac (primeiros 16 hex): 2277cf004aa6aaee30786b83d943580d

> /dh_show
[DH] Sessao com Bob:
      Z     (16 hex): d1c34aa3f0925ac33c88bcf70c96b88d
      K_enc (16 hex): 86b4176ad61dfcc56b51a8a23b8c0af8
      K_mac (16 hex): 2277cf004aa6aaee30786b83d943580d
> /send Bob mensagem cifrada sem assinatura
[MSG] Mensagem cifrada enviada para Bob.
> /send_signed Bob mensagem assinada pela Alice # o Bob ainda nao pediu a chave publica da Alice
[MSG] Mensagem CIFRADA + ASSINADA enviada para Bob.
> /send_signed Bob outra mensagem assinada pela Alice # o Bob ja pediu a chave publica da Alice
[MSG] Mensagem CIFRADA + ASSINADA enviada para Bob.
> /send Bob !upper esta mensagem vai ser modificada # começa pela palavra !upper, e o server modifica
[MSG] Mensagem cifrada enviada para Bob.
> /send_signed Bob !upper mensagem assinada e modificada pelo servidor
[MSG] Mensagem CIFRADA + ASSINADA enviada para Bob.
> /quit
[INFO] Cliente terminado.


Terminal 3:
$ python3 client.py 
[INFO] A ligar ao servidor em 127.0.0.1:5000...
OK Ligado ao ChatWithBackdoor v3.1. Use REGISTER ou LOGIN.
Escolhe um username (identidade local): Bob
[INFO] A usar chaves existentes: Bob_priv.pem, Bob_pub.pem
Comandos (antes do LOGIN):
  /register  -> registar username + chave publica no servidor
  /login     -> autenticar com assinatura de nonce
  /quit      -> sair
-----------------------------------------------------
> /register
OK REGISTER
> /login
NONCE cL91vtLOjjx6zoHkJ3/Nc1u4kQEP+G0W3Srnvfvyxe4=
OK LOGIN
[SERVIDOR] Bob autenticou-se e entrou no chat.

> FROM Alice: mensagem em plaintext, sem ser cifrada

-----------------------------------------------------
[INFO] Autenticado! Agora podes usar o chat, DH e mensagens cifradas.
Comandos (chat + DH):
  /send <dest> <mensagem>       -> enviar mensagem CIFRADA (AES-CBC + HMAC + backdoor)
  /send_signed <dest> <mensagem>-> enviar mensagem CIFRADA + ASSINADA digitalmente
  /list                         -> listar utilizadores online
  /getpk <user>                 -> pedir chave publica RSA de <user> (para verificar assinaturas)
  /dh_start <user>              -> iniciar DH efemero com <user>
  /dh_show                      -> mostrar sessoes DH e chaves derivadas
  /quit                         -> sair
-----------------------------------------------------
> [DH] Recebido DH_INIT_FROM Alice. Sessao DH criada.
[DH]   Z (primeiros 16 hex): d1c34aa3f0925ac33c88bcf70c96b88d
[DH]   K_enc (primeiros 16 hex): 86b4176ad61dfcc56b51a8a23b8c0af8
[DH]   K_mac (primeiros 16 hex): 2277cf004aa6aaee30786b83d943580d
> /dh_show
[DH] Sessao com Alice:
      Z     (16 hex): d1c34aa3f0925ac33c88bcf70c96b88d
      K_enc (16 hex): 86b4176ad61dfcc56b51a8a23b8c0af8
      K_mac (16 hex): 2277cf004aa6aaee30786b83d943580d
> FROM Alice [cifrado+HMAC]: mensagem cifrada sem assinatura
FROM Alice [cifrado+HMAC][SEM PK PARA VERIFICAR]: mensagem assinada pela Alice
[INFO] Usa /getpk Alice para poderes verificar assinaturas desse utilizador.

> /getpk Alice # o Bob pede chave publica da Alice
> [INFO] Chave publica de Alice recebida e guardada (294 bytes DER).
FROM Alice [cifrado+HMAC+ASSIN_OK]: outra mensagem assinada pela Alice
FROM Alice [cifrado+HMAC]: ESTA MENSAGEM VAI SER MODIFICADA
FROM Alice [cifrado+HMAC+ASSIN_FAIL]: MENSAGEM ASSINADA E MODIFICADA PELO SERVIDOR
[SERVIDOR] Alice saiu do chat.

> /quit
[INFO] Cliente terminado.
"""

