"""
ChatWithBackdoor - Servidor
============================
Servidor central que:
  - Regista utilizadores com chaves públicas RSA
  - Autentica com assinatura digital de nonce
  - Encaminha mensagens cifradas entre clientes
  - BACKDOOR: Decifra, lê e pode modificar todas as mensagens

Backdoor implementada via:
  blob = AES-ECB(K_SERVER, K_enc)
  K_enc recuperada com AES-ECB-Decrypt
  K_mac = SHA256(K_enc)
"""

import socket
import threading
import base64
import os
import hashlib
import hmac

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympadding

HOST = "127.0.0.1"
PORT = 5000

# Chave secreta do servidor (backdoor - cliente também a conhece para criar blob)(eventual vulnerabilidade num ambiente real pois está hardcoded)
K_SERVER = b"0123456789abcdef"

# Base de dados em memória
users = {}  # username -> RSAPublicKey
online_clients = {}  # username -> socket
lock = threading.Lock()
pending_nonces = {}  # socket -> (username, nonce_bytes)


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
    return hmac.new(key, data, hashlib.sha256).digest()


def load_public_key_from_der(der_bytes: bytes):
    """
    Carrega a chave pública RSA de bytes DER.
    
    Input: der_bytes (bytes)
    Output: RSAPublicKey object
    """
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
                pass


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
    current_username = None
    authenticated = False

    try:
        conn.sendall(b"OK Ligado ao ChatWithBackdoor v3.1. Use REGISTER ou LOGIN.\n")

        while True:
            data = conn.recv(4096)
            if not data:
                break

            line = data.decode("utf-8", errors="ignore").strip()
            if not line:
                continue

            # REGISTER <username> <pubkey_der_base64>
            if line.startswith("REGISTER "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    conn.sendall(b"ERR Uso: REGISTER <username> <pubkey_der_base64>\n")
                    continue
                _, username, b64_pk = parts
                username = username.strip()

                if not username:
                    conn.sendall(b"ERR Username vazio\n")
                    continue

                try:
                    der_bytes = base64.b64decode(b64_pk.encode("utf-8"), validate=True)
                    pubkey = load_public_key_from_der(der_bytes)
                except Exception:
                    conn.sendall(b"ERR Chave publica invalida (base64/DER)\n")
                    continue

                with lock:
                    if username in users:
                        conn.sendall(b"ERR Username ja registado\n")
                        continue
                    users[username] = pubkey

                conn.sendall(b"OK REGISTER\n")
                continue

            # LOGIN <username> - pedir nonce para assinatura
            if line.startswith("LOGIN "):
                parts = line.split(" ", 1)
                if len(parts) < 2:
                    conn.sendall(b"ERR Uso: LOGIN <username>\n")
                    continue
                _, username = parts
                username = username.strip()

                with lock:
                    if username not in users:
                        conn.sendall(b"ERR Username nao registado\n")
                        continue

                # Gerar nonce aleatório
                nonce = os.urandom(32)
                b64_nonce = base64.b64encode(nonce).decode("utf-8")

                with lock:
                    pending_nonces[conn] = (username, nonce)

                conn.sendall(f"NONCE {b64_nonce}\n".encode("utf-8"))
                continue

            # LOGIN_SIG <username> <signature_base64>
            if line.startswith("LOGIN_SIG "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    conn.sendall(b"ERR Uso: LOGIN_SIG <username> <signature_base64>\n")
                    continue
                _, username, b64_sig = parts
                username = username.strip()

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

                if nonce_username != username:
                    conn.sendall(b"ERR Username nao corresponde ao nonce pendente\n")
                    continue

                with lock:
                    pubkey = users.get(username)

                if pubkey is None:
                    conn.sendall(b"ERR Username nao registado\n")
                    continue

                # Verificar assinatura
                ok = verify_signature(pubkey, nonce, signature)
                if not ok:
                    conn.sendall(b"ERR LOGIN assinatura invalida\n")
                    continue

                # Autenticação bem-sucedida
                authenticated = True
                current_username = username

                with lock:
                    pending_nonces.pop(conn, None)
                    online_clients[username] = conn

                conn.sendall(b"OK LOGIN\n")
                broadcast_system_message(f"{username} autenticou-se e entrou no chat.")
                continue

            # Comandos que requerem autenticação
            if not authenticated:
                conn.sendall(b"ERR Precisa de fazer LOGIN primeiro\n")
                continue

            # GET_PK <username> - obter chave pública de utilizador
            if line.startswith("GET_PK "):
                parts = line.split(" ", 1)
                if len(parts) < 2:
                    conn.sendall(b"ERR Uso: GET_PK <username>\n")
                    continue
                _, target_user = parts
                target_user = target_user.strip()

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

            # DH_INIT <dest> <b64_dh_pub> - encaminhar para destinatário
            if line.startswith("DH_INIT "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    conn.sendall(b"ERR Uso: DH_INIT <dest> <b64_dh_pub>\n")
                    continue
                _, dest, b64_dh_pub = parts
                dest = dest.strip()

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

            # DH_REPLY <dest> <b64_dh_pub> - encaminhar resposta DH
            if line.startswith("DH_REPLY "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    conn.sendall(b"ERR Uso: DH_REPLY <dest> <b64_dh_pub>\n")
                    continue
                _, dest, b64_dh_pub = parts
                dest = dest.strip()

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

            # LIST - listar utilizadores online
            if line == "LIST":
                with lock:
                    names = ", ".join(sorted(online_clients.keys()))
                conn.sendall(f"USERS {names}\n".encode("utf-8"))
                continue

            # TO <dest> <mensagem> - mensagem em claro (debug apenas)
            if line.startswith("TO "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    conn.sendall(b"ERR Uso: TO <dest> <mensagem>\n")
                    continue

                _, dest, msg = parts
                dest = dest.strip()

                with lock:
                    dest_sock = online_clients.get(dest)

                if dest_sock is None:
                    conn.sendall(f"ERR Utilizador '{dest}' nao esta online\n".encode("utf-8"))
                    continue

                out = f"FROM {current_username}: {msg}\n".encode("utf-8")
                try:
                    dest_sock.sendall(out)
                except Exception:
                    conn.sendall(f"ERR Falha ao enviar para {dest}\n".encode("utf-8"))
                continue

            # MSG <dest> <b64_header> <b64_blob> <b64_iv> <b64_cipher> <b64_tag>
            # BACKDOOR: servidor decifra, lê e pode modificar a mensagem
            if line.startswith("MSG "):
                parts = line.split(" ", 6)
                if len(parts) < 7:
                    conn.sendall(
                        b"ERR Uso: MSG <dest> <b64_header> <b64_blob> <b64_iv> <b64_cipher> <b64_tag>\n"
                    )
                    continue

                _, dest, b64_header, b64_blob, b64_iv, b64_cipher, b64_tag = parts

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

                # BACKDOOR: Recuperar K_enc do blob
                try:
                    k_enc = aes_decrypt_ecb(K_SERVER, blob)
                except Exception:
                    conn.sendall(b"ERR Falha ao recuperar K_enc a partir do blob\n")
                    continue

                # Derivar K_mac
                k_mac = hashlib.sha256(k_enc).digest()

                # Verificar HMAC
                calc_tag = hmac_sha256(k_mac, header + blob + iv + cipher)
                if not hmac.compare_digest(calc_tag, tag):
                    conn.sendall(b"ERR HMAC invalido (mensagem corrompida)\n")
                    continue

                # Decifrar mensagem
                try:
                    plaintext = aes_decrypt_cbc(k_enc, iv, cipher)
                except Exception:
                    conn.sendall(b"ERR Falha ao decifrar mensagem\n")
                    continue

                try:
                    plaintext_str = plaintext.decode("utf-8")
                except Exception:
                    plaintext_str = plaintext.decode("utf-8", errors="replace")

                # BACKDOOR: Mostrar mensagem decifrada
                print(f"[BACKDOOR] {current_username} -> {dest}: {plaintext_str}")

                # Modificação opcional da mensagem (exemplo: comando !upper)
                msg_mod = plaintext_str
                if msg_mod.startswith("!upper "):
                    msg_mod = msg_mod[len("!upper ") :].upper()

                plaintext_out = msg_mod.encode("utf-8")

                # Recifrar com as mesmas chaves
                cipher_out = aes_encrypt_cbc(k_enc, iv, plaintext_out)
                tag_out = hmac_sha256(k_mac, header + blob + iv + cipher_out)

                b64_cipher_out = base64.b64encode(cipher_out).decode("utf-8")
                b64_tag_out = base64.b64encode(tag_out).decode("utf-8")

                # Enviar ao destinatário
                wire = (
                    f"MSG_FROM {current_username} "
                    f"{b64_header} {b64_blob} {b64_iv} {b64_cipher_out} {b64_tag_out}\n"
                )
                try:
                    dest_sock.sendall(wire.encode("utf-8"))
                except Exception:
                    conn.sendall(f"ERR Falha ao enviar MSG para {dest}\n".encode("utf-8"))
                continue

            # QUIT - desconectar
            if line == "QUIT":
                conn.sendall(b"OK Adeus\n")
                break

            # Comando desconhecido
            conn.sendall(b"ERR Comando desconhecido\n")

    except Exception as e:
        print(f"[ERRO] Excecao com {addr}: {e}")

    finally:
        with lock:
            pending_nonces.pop(conn, None)
            if current_username and online_clients.get(current_username) is conn:
                del online_clients[current_username]

        if current_username:
            broadcast_system_message(f"{current_username} saiu do chat.")

        conn.close()
        print(f"[DEBUG] Ligacao terminada com {addr}")


def main():
    """
    Função principal do servidor.
    
    Inicia socket TCP e aceita conexões em threads separadas.
    """
    print(f"[INFO] Servidor a escutar em {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((HOST, PORT))
        server_sock.listen()

        while True:
            conn, addr = server_sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()


if __name__ == "__main__":
    main()