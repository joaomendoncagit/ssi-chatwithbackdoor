#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ===============================================================
# CHATWITHBACKDOOR - SERVIDOR V3 (BACKDOOR + HMAC)
# ===============================================================
# Funcionalidades:
#   - Registo de utilizadores com chave publica RSA
#   - Autenticacao forte: LOGIN com assinatura digital de nonce
#   - Diretoria de chaves publicas: GET_PK
#   - Encaminhamento de mensagens em claro (TO)   [modo antigo, so para debug]
#   - Encaminhamento de mensagens cifradas (MSG)  [modo novo, com backdoor]
#   - Backdoor:
#       IV = AES-ECB_Encrypt(K_SERVER, K_enc)
#       K_enc = AES-ECB_Decrypt(K_SERVER, IV)
#       K_mac = SHA256(K_enc)
#       tag   = HMAC_SHA256(K_mac, header || IV || C)
# ===============================================================

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

# Chave secreta do servidor para a backdoor (AES-128)
# (Na teoria, so o servidor devia conhecer esta chave.)
K_SERVER = b"0123456789abcdef"  # 16 bytes

# Utilizadores registados: username -> public_key (objeto cryptography)
users = {}
# Clientes online e autenticados: username -> socket
online_clients = {}
# Lock global
lock = threading.Lock()
# Nonces de login pendentes: conn -> (username, nonce_bytes)
pending_nonces = {}


# ---------------------------------------------------
# AUXILIARES CRIPTO (AES + HMAC)
# ---------------------------------------------------
def aes_encrypt_ecb(key: bytes, block: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(block) + enc.finalize()


def aes_decrypt_ecb(key: bytes, block: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    dec = cipher.decryptor()
    return dec.update(block) + dec.finalize()


def aes_encrypt_cbc(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    padder = sympadding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def aes_decrypt_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = sympadding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


# ---------------------------------------------------
# FUNCOES RSA / LOGIN
# ---------------------------------------------------
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


# ---------------------------------------------------
# THREAD POR CLIENTE
# ---------------------------------------------------
def handle_client(conn: socket.socket, addr):
    print(f"[DEBUG] Ligacao de {addr}")
    current_username = None
    authenticated = False

    try:
        conn.sendall(b"OK Ligado ao ChatWithBackdoor v3. Use REGISTER ou LOGIN.\n")

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

                ok = verify_signature(pubkey, nonce, signature)
                if not ok:
                    conn.sendall(b"ERR LOGIN assinatura invalida\n")
                    continue

                authenticated = True
                current_username = username

                with lock:
                    pending_nonces.pop(conn, None)
                    online_clients[username] = conn

                conn.sendall(b"OK LOGIN\n")
                broadcast_system_message(f"{username} autenticou-se e entrou no chat.")
                continue

            # ---------------------------------------------------
            # A partir daqui, so autenticado
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
            # 5) DH_INIT: igual versao anterior (encaminhar)
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
            # 6) DH_REPLY: igual versao anterior (encaminhar)
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
            # 8) TO <dest> <mensagem>  (modo antigo, em claro)
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
            # 9) MSG <dest> <b64_header> <b64_iv> <b64_cipher> <b64_tag>
            #     -> servidor usa backdoor para ler/alterar
            # ---------------------------------------------------
            if line.startswith("MSG "):
                parts = line.split(" ", 5)
                if len(parts) < 6:
                    conn.sendall(b"ERR Uso: MSG <dest> <b64_header> <b64_iv> <b64_cipher> <b64_tag>\n")
                    continue

                _, dest, b64_header, b64_iv, b64_cipher, b64_tag = parts

                with lock:
                    dest_sock = online_clients.get(dest)

                if dest_sock is None:
                    conn.sendall(f"ERR Utilizador '{dest}' nao esta online\n".encode("utf-8"))
                    continue

                try:
                    header = base64.b64decode(b64_header.encode("utf-8"), validate=True)
                    iv = base64.b64decode(b64_iv.encode("utf-8"), validate=True)
                    cipher = base64.b64decode(b64_cipher.encode("utf-8"), validate=True)
                    tag = base64.b64decode(b64_tag.encode("utf-8"), validate=True)
                except Exception:
                    conn.sendall(b"ERR MSG campos base64 invalidos\n")
                    continue

                # 1) Recuperar K_enc a partir do IV (backdoor)
                try:
                    k_enc = aes_decrypt_ecb(K_SERVER, iv)
                except Exception:
                    conn.sendall(b"ERR Falha ao recuperar K_enc a partir do IV\n")
                    continue

                # 2) Derivar K_mac
                k_mac = hashlib.sha256(k_enc).digest()

                # 3) Verificar HMAC
                calc_tag = hmac_sha256(k_mac, header + iv + cipher)
                if not hmac.compare_digest(calc_tag, tag):
                    conn.sendall(b"ERR HMAC invalido (mensagem corrompida)\n")
                    continue

                # 4) Decifrar mensagem
                try:
                    plaintext = aes_decrypt_cbc(k_enc, iv, cipher)
                except Exception:
                    conn.sendall(b"ERR Falha ao decifrar mensagem\n")
                    continue

                try:
                    plaintext_str = plaintext.decode("utf-8")
                except Exception:
                    plaintext_str = plaintext.decode("utf-8", errors="replace")

                # 5) Mostrar no servidor (backdoor)
                print(f"[BACKDOOR] {current_username} -> {dest}: {plaintext_str}")

                # 6) Opcional: alterar mensagem
                msg_mod = plaintext_str
                # Exemplo simples: se começar por "!upper", o servidor altera para maiusculas
                if msg_mod.startswith("!upper "):
                    msg_mod = msg_mod[len("!upper "):].upper()

                plaintext_out = msg_mod.encode("utf-8")

                # 7) Recifrar / recalcular HMAC
                cipher_out = aes_encrypt_cbc(k_enc, iv, plaintext_out)
                tag_out = hmac_sha256(k_mac, header + iv + cipher_out)

                b64_cipher_out = base64.b64encode(cipher_out).decode("utf-8")
                b64_tag_out = base64.b64encode(tag_out).decode("utf-8")

                # 8) Enviar ao destinatario
                wire = f"MSG_FROM {current_username} {b64_header} {b64_iv} {b64_cipher_out} {b64_tag_out}\n"
                try:
                    dest_sock.sendall(wire.encode("utf-8"))
                except Exception:
                    conn.sendall(f"ERR Falha ao enviar MSG para {dest}\n".encode("utf-8"))
                continue

            # ---------------------------------------------------
            # 10) QUIT
            # ---------------------------------------------------
            if line == "QUIT":
                conn.sendall(b"OK Adeus\n")
                break

            # ---------------------------------------------------
            # 11) Comando desconhecido
            # ---------------------------------------------------
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
[DEBUG] Ligacao de ('127.0.0.1', 38976)
[DEBUG] Ligacao de ('127.0.0.1', 39666)
[BACKDOOR] Alice -> Bob: mensagem assinada pela Alice||SIG||j6NKqZpXBXuHk6Wq4KA6u6wa3JVhJF8XOmXYWuzyGcKj8+3AVm3kQWmFstGWdfyzcF3RG6x3y+uXwDP/sET7Zw60ErFsp5eqg4OBU4NML1ItggAknMqnmjgfRYwwFDRL1lBaczCK1e4HGKcA+vxhLYF1T+fbh5EZUJulYx22brbyVMh3mX9RvaW/XqfHAffunCoMl/lVroQx5oU6iEFuf0/5YVQMXwBkmbG/NjcnyMIA+EQAhvbrLOJotxfJwm4Z53S7OgL79G6bM9rLCmHHes5ywwprUQX5EJY2OZz+jkkKRaFJUPQBRlq5K2GzvCYz/PMmn/eqbdd3sXPSDZIw6Q==
[BACKDOOR] Alice -> Bob: outra mensagem assinada pela Alice||SIG||dF/I1twL29gNWf5qfKwPryLNx5Vf4xISe61cZ1DTnuYenBcbvg+lOZHEmkNZ2lljRBZZ7tQZmbpSPGp2WZBjrHImjCopG+X/DFe9lbI02r0eiXGDCl2BZh3jXxQQoaWrVZVZh3dO/2xoYHgqWT9eGnEJIWN85pqmciaatzxMDYEFuoRz9ENNlXSHBd6FIhvFUqRRrckJzZxwNZqtMxjM9lG4cEqsB7VqStBzob4V+sDSaR3CiTRfTCIQdU+XWDhJM6SIUSJHn/j1G2mII3zEHpOR82DLNg50z7mAXMdzmag+rxEqixJW2aSF/jM06pGfwKfmOnqdQ3RkAoycaAufvA==
[DEBUG] Ligacao terminada com ('127.0.0.1', 38976)
[DEBUG] Ligacao terminada com ('127.0.0.1', 39666)


Terminal 2:
$ python3 client.py
[INFO] A ligar ao servidor em 127.0.0.1:5000...
OK Ligado ao ChatWithBackdoor v3. Use REGISTER ou LOGIN.
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
NONCE /nQMHDTKuTlASCidW8ih7lVNs/+DBLgosuAxz2UBPlg=
OK LOGIN
[SERVIDOR] Alice autenticou-se e entrou no chat.
-----------------------------------------------------
[INFO] Autenticado! Agora podes usar o chat, DH e mensagens cifradas.
Comandos (chat + DH):
  /to <dest> <mensagem>         -> enviar mensagem CIFRADA (AES-CBC + HMAC + backdoor)
  /send <dest> <mensagem>       -> alias para /to (envio cifrado)
  /send_signed <dest> <mensagem>-> enviar mensagem CIFRADA + ASSINADA digitalmente
  /list                         -> listar utilizadores online
  /getpk <user>                 -> pedir chave publica RSA de <user> (para verificar assinaturas)
  /dh_start <user>              -> iniciar DH efemero com <user>
  /dh_show                      -> mostrar sessoes DH e chaves derivadas
  /quit                         -> sair
-----------------------------------------------------
> [SERVIDOR] Bob autenticou-se e entrou no chat.
             
> /dh_start Bob
[DH] Iniciado DH com Bob. A aguardar DH_REPLY_FROM Bob...
> [DH] Sessao DH com Bob COMPLETA (lado iniciador).
[DH]   Z (primeiros 16 hex): fab4008874d0a30f5ba889df132dfbdd
[DH]   K_enc (primeiros 16 hex): 6fb05593b7895f33868d36f81868746f
[DH]   K_mac (primeiros 16 hex): 86a0ec5c5d67fb6f0bbd968194126cb8

> /dh_show
[DH] Sessao com Bob:
      Z     (16 hex): fab4008874d0a30f5ba889df132dfbdd
      K_enc (16 hex): 6fb05593b7895f33868d36f81868746f
      K_mac (16 hex): 86a0ec5c5d67fb6f0bbd968194126cb8
> /getpk Bob
> [INFO] Chave publica de Bob recebida e guardada (294 bytes DER).
                                             
> /send_signed Bob mensagem assinada pela Alice
[MSG] Mensagem CIFRADA + ASSINADA enviada para Bob.
> /send_signed Bob outra mensagem assinada pela Alice
[MSG] Mensagem CIFRADA + ASSINADA enviada para Bob.
> /quit
[INFO] Cliente terminado.


Terminal 3:
$ python3 client.py
[INFO] A ligar ao servidor em 127.0.0.1:5000...
OK Ligado ao ChatWithBackdoor v3. Use REGISTER ou LOGIN.
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
NONCE iLd3pVNLwCLB9HY6hBx+dqK0VLTmY1euv653Ei6ZbXc=
OK LOGIN
-----------------------------------------------------
[INFO] Autenticado! Agora podes usar o chat, DH e mensagens cifradas.
Comandos (chat + DH):
  /to <dest> <mensagem>         -> enviar mensagem CIFRADA (AES-CBC + HMAC + backdoor)
  /send <dest> <mensagem>       -> alias para /to (envio cifrado)
  /send_signed <dest> <mensagem>-> enviar mensagem CIFRADA + ASSINADA digitalmente
  /list                         -> listar utilizadores online
  /getpk <user>                 -> pedir chave publica RSA de <user> (para verificar assinaturas)
  /dh_start <user>              -> iniciar DH efemero com <user>
  /dh_show                      -> mostrar sessoes DH e chaves derivadas
  /quit                         -> sair
-----------------------------------------------------
[SERVIDOR] Bob autenticou-se e entrou no chat.
> [DH] Recebido DH_INIT_FROM Alice. Sessao DH criada.
[DH]   Z (primeiros 16 hex): fab4008874d0a30f5ba889df132dfbdd
[DH]   K_enc (primeiros 16 hex): 6fb05593b7895f33868d36f81868746f
[DH]   K_mac (primeiros 16 hex): 86a0ec5c5d67fb6f0bbd968194126cb8
FROM Alice [cifrado+HMAC][SEM PK PARA VERIFICAR]: mensagem assinada pela Alice
[INFO] Usa /getpk Alice para poderes verificar assinaturas desse utilizador.

> /getpk Alice
> [INFO] Chave publica de Alice recebida e guardada (294 bytes DER).
FROM Alice [cifrado+HMAC+ASSIN_OK]: outra mensagem assinada pela Alice
[SERVIDOR] Alice saiu do chat.

> /quit
[INFO] Cliente terminado.
"""
