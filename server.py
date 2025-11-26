#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ===============================================================
# CHATWITHBACKDOOR - SERVIDOR V2
# ===============================================================
# Funcionalidades:
#   - Registo de utilizadores com chave publica RSA
#   - Autenticacao forte: LOGIN com assinatura digital de nonce
#   - Diretoria de chaves publicas: GET_PK
#   - Encaminhamento de mensagens em claro (TO)
#   - Encaminhamento de parametros Diffie-Hellman efemeros:
#         DH_INIT  / DH_INIT_FROM
#         DH_REPLY / DH_REPLY_FROM
#
# Protocolo (texto, uma linha por comando):
#
#   REGISTER <username> <pubkey_der_base64>
#   LOGIN <username>
#   LOGIN_SIG <username> <signature_base64>
#
#   GET_PK <username>
#       -> PK <username> <pubkey_der_base64>
#
#   DH_INIT <dest> <b64_dh_pub>
#       -> para dest: DH_INIT_FROM <orig> <b64_dh_pub>
#
#   DH_REPLY <dest> <b64_dh_pub>
#       -> para dest: DH_REPLY_FROM <orig> <b64_dh_pub>
#
#   LIST
#   TO <dest> <mensagem...>
#   QUIT
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
      - REGISTER (opcional, so 1x para criar utilizador)
      - LOGIN + LOGIN_SIG para autenticar
      - Depois pode usar GET_PK / DH_* / LIST / TO / QUIT
    """
    print(f"[DEBUG] Ligacao de {addr}")
    current_username = None
    authenticated = False

    try:
        # Mensagem inicial opcional
        conn.sendall(b"OK Ligado ao ChatWithBackdoor v2. Use REGISTER ou LOGIN.\n")

        while True:
            data = conn.recv(4096)
            if not data:
                break

            line = data.decode("utf-8", errors="ignore").strip()
            if not line:
                continue

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
            # A partir daqui, so comandos para utilizador autenticado
            # ---------------------------------------------------
            if not authenticated:
                conn.sendall(b"ERR Precisa de fazer LOGIN primeiro\n")
                continue

            # ---------------------------------------------------
            # 4) GET_PK <username>
            # ---------------------------------------------------
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

            # ---------------------------------------------------
            # 5) DH_INIT <dest> <b64_dh_pub>
            #     Encaminhar para dest: DH_INIT_FROM <orig> <b64_dh_pub>
            # ---------------------------------------------------
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

            # ---------------------------------------------------
            # 6) DH_REPLY <dest> <b64_dh_pub>
            #     Encaminhar para dest: DH_REPLY_FROM <orig> <b64_dh_pub>
            # ---------------------------------------------------
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

            # ---------------------------------------------------
            # 7) LIST
            # ---------------------------------------------------
            if line == "LIST":
                with lock:
                    names = ", ".join(sorted(online_clients.keys()))
                conn.sendall(f"USERS {names}\n".encode("utf-8"))
                continue

            # ---------------------------------------------------
            # 8) TO <dest> <mensagem>
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
            # 9) QUIT
            # ---------------------------------------------------
            if line == "QUIT":
                conn.sendall(b"OK Adeus\n")
                break

            # ---------------------------------------------------
            # 10) Comando desconhecido
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
[DEBUG] Ligacao de ('127.0.0.1', 40478)
[DEBUG] Ligacao de ('127.0.0.1', 54910)


Terminal 2:
$ python3 client.py
[INFO] A ligar ao servidor em 127.0.0.1:5000...
OK Ligado ao ChatWithBackdoor v2. Use REGISTER ou LOGIN.
Escolhe um username (identidade local): Alice
[INFO] A gerar par de chaves RSA para 'Alice'...
[INFO] Chaves guardadas em Alice_priv.pem e Alice_pub.pem
Comandos (antes do LOGIN):
  /register  -> registar username + chave publica no servidor
  /login     -> autenticar com assinatura de nonce
  /quit      -> sair
-----------------------------------------------------
> /register
OK REGISTER
> /login
NONCE AGRATHtmOPtlYedKM0Td8E99YxVhNcMWiv83c4SezXo=
OK LOGIN
[SERVIDOR] Alice autenticou-se e entrou no chat.
-----------------------------------------------------
[INFO] Autenticado! Agora podes usar o chat e DH.
Comandos (chat + DH):
  /to <dest> <mensagem>  -> enviar mensagem para outro utilizador autenticado
  /list                  -> listar utilizadores online
  /getpk <user>          -> pedir chave publica RSA de <user>
  /dh_start <user>       -> iniciar DH efemero com <user>
  /dh_show               -> mostrar sessoes DH e chaves derivadas
  /quit                  -> sair
-----------------------------------------------------
> /list
> USERS Alice
/getpk Bob
> ERR Username nao registado
[SERVIDOR] Bob autenticou-se e entrou no chat.

> /dh_start Bob
[DH] Iniciado DH com Bob. A aguardar DH_REPLY_FROM Bob...
> [DH] Sessao DH com Bob COMPLETA (lado iniciador).
[DH]   Z (primeiros 16 hex): c07e03b7b52b06bb26302e32b43fc7d3
[DH]   K_enc (primeiros 16 hex): 0eb112e82bf8f7fa44118349eb1107eb
[DH]   K_mac (primeiros 16 hex): 762f7ecd10eedc36b074399e413a2290

> /dh_show
[DH] Sessao com Bob:
      Z     (16 hex): c07e03b7b52b06bb26302e32b43fc7d3
      K_enc (16 hex): 0eb112e82bf8f7fa44118349eb1107eb
      K_mac (16 hex): 762f7ecd10eedc36b074399e413a2290
> /to Bob Ola, Bob!
> /list
> USERS Alice, Bob



Terminal 3:
$ python3 client.py
[INFO] A ligar ao servidor em 127.0.0.1:5000...
OK Ligado ao ChatWithBackdoor v2. Use REGISTER ou LOGIN.
Escolhe um username (identidade local): Bob
[INFO] A gerar par de chaves RSA para 'Bob'...
[INFO] Chaves guardadas em Bob_priv.pem e Bob_pub.pem
Comandos (antes do LOGIN):
  /register  -> registar username + chave publica no servidor
  /login     -> autenticar com assinatura de nonce
  /quit      -> sair
-----------------------------------------------------
> /register
OK REGISTER
> /login
NONCE rLNIXRO0pqSmR/caeEwpYSXvZY5v29SyoUlnqEnBLjU=
OK LOGIN
-----------------------------------------------------
[INFO] Autenticado! Agora podes usar o chat e DH.
Comandos (chat + DH):
  /to <dest> <mensagem>  -> enviar mensagem para outro utilizador autenticado
  /list                  -> listar utilizadores online
  /getpk <user>          -> pedir chave publica RSA de <user>
  /dh_start <user>       -> iniciar DH efemero com <user>
  /dh_show               -> mostrar sessoes DH e chaves derivadas
  /quit                  -> sair
-----------------------------------------------------
[SERVIDOR] Bob autenticou-se e entrou no chat.
> [DH] Recebido DH_INIT_FROM Alice. Sessao DH criada.
[DH]   Z (primeiros 16 hex): c07e03b7b52b06bb26302e32b43fc7d3
[DH]   K_enc (primeiros 16 hex): 0eb112e82bf8f7fa44118349eb1107eb
[DH]   K_mac (primeiros 16 hex): 762f7ecd10eedc36b074399e413a2290

> /dh_show
[DH] Sessao com Alice:
      Z     (16 hex): c07e03b7b52b06bb26302e32b43fc7d3
      K_enc (16 hex): 0eb112e82bf8f7fa44118349eb1107eb
      K_mac (16 hex): 762f7ecd10eedc36b074399e413a2290
> FROM Alice: Ola, Bob!

"""
