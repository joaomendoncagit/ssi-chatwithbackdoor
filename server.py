#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ===============================================================
# CHATWITHBACKDOOR - SERVIDOR V1
# ===============================================================
# Funcionalidades:
#   - Registo de utilizadores com chave pública RSA
#   - Autenticação forte: LOGIN com assinatura digital de nonce
#   - Encaminhamento de mensagens em claro (ainda sem cifrar)
#
# Protocolo (texto, uma linha por comando):
#
#   REGISTER <username> <pubkey_der_base64>
#       -> Regista username + chave pública (DER codificado em base64)
#
#   LOGIN <username>
#       -> Servidor responde: NONCE <nonce_base64>
#
#   LOGIN_SIG <username> <signature_base64>
#       -> Servidor verifica assinatura do nonce anterior usando pk do username
#       -> Se OK: "OK LOGIN"
#
#   LIST
#       -> USERS <lista_de_usernames_ligados>
#
#   TO <dest> <mensagem...>
#       -> Envia: "FROM <origem>: <mensagem...>" ao destinatário
#
#   QUIT
#       -> Termina ligação do cliente
#
# ===============================================================

import socket
import threading
import base64
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

HOST = "127.0.0.1"
PORT = 5000

# Utilizadores registados: username -> public_key (objeto cryptography)
users = {}
# Clientes online e autenticados: username -> socket
online_clients = {}
# Lock global
lock = threading.Lock()
# Nonces de login pendentes: conn -> (username, nonce_bytes)
pending_nonces = {}


def load_public_key_from_der(der_bytes: bytes):
    return serialization.load_der_public_key(der_bytes)


def verify_signature(pubkey, nonce: bytes, signature: bytes) -> bool:
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
    """Envia uma mensagem de sistema para todos os clientes autenticados."""
    with lock:
        for sock in online_clients.values():
            try:
                sock.sendall(f"[SERVIDOR] {msg}\n".encode("utf-8"))
            except Exception:
                pass


def handle_client(conn: socket.socket, addr):
    """
    Thread por cliente.

    Cada cliente passa por:
      - REGISTER (opcional, só 1x para criar utilizador)
      - LOGIN + LOGIN_SIG para autenticar
      - Depois pode usar LIST / TO / QUIT
    """
    print(f"[DEBUG] Ligacao de {addr}")
    current_username = None
    authenticated = False

    try:
        # Mensagem inicial opcional
        conn.sendall(b"OK Ligado ao ChatWithBackdoor v1. Use REGISTER ou LOGIN.\n")

        while True:
            data = conn.recv(4096)
            if not data:
                break

            line = data.decode("utf-8", errors="ignore").strip()
            if not line:
                continue

            # Debug opcional
            # print(f"[DEBUG] Recebido de {addr}: {line}")

            # ---------------------------------------------------
            # 1) REGISTO
            # ---------------------------------------------------
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

            # ---------------------------------------------------
            # 2) LOGIN - PEDIR NONCE
            # ---------------------------------------------------
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

                # Gerar nonce e guardar
                nonce = os.urandom(32)
                b64_nonce = base64.b64encode(nonce).decode("utf-8")

                with lock:
                    pending_nonces[conn] = (username, nonce)

                conn.sendall(f"NONCE {b64_nonce}\n".encode("utf-8"))
                continue

            # ---------------------------------------------------
            # 3) LOGIN_SIG - ASSINATURA DO NONCE
            # ---------------------------------------------------
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

                # Autenticado!
                authenticated = True
                current_username = username

                with lock:
                    # remover nonce pendente
                    pending_nonces.pop(conn, None)

                    # registar cliente online
                    online_clients[username] = conn

                conn.sendall(b"OK LOGIN\n")
                broadcast_system_message(f"{username} autenticou-se e entrou no chat.")
                continue

            # ---------------------------------------------------
            # A partir daqui, só comandos para utilizador autenticado
            # ---------------------------------------------------
            if not authenticated:
                conn.sendall(b"ERR Precisa de fazer LOGIN primeiro\n")
                continue

            # ---------------------------------------------------
            # 4) LIST
            # ---------------------------------------------------
            if line == "LIST":
                with lock:
                    names = ", ".join(sorted(online_clients.keys()))
                conn.sendall(f"USERS {names}\n".encode("utf-8"))
                continue

            # ---------------------------------------------------
            # 5) TO <dest> <mensagem>
            # ---------------------------------------------------
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

            # ---------------------------------------------------
            # 6) QUIT
            # ---------------------------------------------------
            if line == "QUIT":
                conn.sendall(b"OK Adeus\n")
                break

            # ---------------------------------------------------
            # 7) Comando desconhecido
            # ---------------------------------------------------
            conn.sendall(b"ERR Comando desconhecido\n")

    except Exception as e:
        print(f"[ERRO] Excecao com {addr}: {e}")

    finally:
        # Limpar estados
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
"""
Terminal 1:
$ python3 server.py
[INFO] Servidor a escutar em 127.0.0.1:5000
[DEBUG] Ligacao de ('127.0.0.1', 47658)
[DEBUG] Ligacao de ('127.0.0.1', 36196)


Terminal 2:
$ python3 client.py
[INFO] A ligar ao servidor em 127.0.0.1:5000...
OK Ligado ao ChatWithBackdoor v1. Use REGISTER ou LOGIN.
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
NONCE TVlEyLgTenYZlMe0SdAhGQ+/wORYeiWR/8fSLkYMqfY=
OK LOGIN
[SERVIDOR] Alice autenticou-se e entrou no chat.
-----------------------------------------------------
[INFO] Autenticado! Agora podes usar o chat.
Comandos (chat):
  /to <dest> <mensagem>  -> enviar mensagem para outro utilizador autenticado
  /list                  -> listar utilizadores online
  /quit                  -> sair
-----------------------------------------------------
> [SERVIDOR] Bob autenticou-se e entrou no chat.
/to Bob Ola Bob, agora sim com LOGIN forte!
> /list
> USERS Alice, Bob


Terminal 3:
$ python3 client.py
[INFO] A ligar ao servidor em 127.0.0.1:5000...
OK Ligado ao ChatWithBackdoor v1. Use REGISTER ou LOGIN.
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
NONCE yB6MB7kllFbSoD4UKldgnzbJlzyN8oQhTQ6Ud3F5Ee8=
OK LOGIN
-----------------------------------------------------
[INFO] Autenticado! Agora podes usar o chat.
Comandos (chat):
  /to <dest> <mensagem>  -> enviar mensagem para outro utilizador autenticado
  /list                  -> listar utilizadores online
  /quit                  -> sair
-----------------------------------------------------
> [SERVIDOR] Bob autenticou-se e entrou no chat.
FROM Alice: Ola Bob, agora sim com LOGIN forte!
/list
> USERS Alice, Bob

"""