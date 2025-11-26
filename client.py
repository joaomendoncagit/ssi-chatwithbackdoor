#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ===============================================================
# CHATWITHBACKDOOR - CLIENTE V1.1
# ===============================================================
# Funcionalidades:
#   - Gera par de chaves RSA localmente (se ainda nao existir)
#   - REGISTO: envia a chave publica para o servidor (síncrono)
#   - LOGIN: autenticação forte com assinatura de nonce (síncrono)
#   - DEPOIS DO LOGIN:
#         - Thread de rececao para imprimir tudo do servidor
#         - Comandos /to, /list, /quit
# ===============================================================

import socket
import threading
import sys
import os
import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

HOST = "127.0.0.1"
PORT = 5000


# ---------------------------------------------------------------
# GESTAO DE CHAVES RSA NO CLIENTE
# ---------------------------------------------------------------
def get_key_filenames(username: str):
    priv_file = f"{username}_priv.pem"
    pub_file = f"{username}_pub.pem"
    return priv_file, pub_file


def generate_rsa_keypair(username: str):
    priv_file, pub_file = get_key_filenames(username)

    print(f"[INFO] A gerar par de chaves RSA para '{username}'...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Guardar chave privada
    with open(priv_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Guardar chave publica
    with open(pub_file, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print(f"[INFO] Chaves guardadas em {priv_file} e {pub_file}")


def load_private_key(username: str):
    priv_file, _ = get_key_filenames(username)
    with open(priv_file, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key_pem(username: str) -> bytes:
    _, pub_file = get_key_filenames(username)
    with open(pub_file, "rb") as f:
        return f.read()


def ensure_keys_exist(username: str):
    priv_file, pub_file = get_key_filenames(username)
    if not (os.path.exists(priv_file) and os.path.exists(pub_file)):
        generate_rsa_keypair(username)
    else:
        print(f"[INFO] A usar chaves existentes: {priv_file}, {pub_file}")


# ---------------------------------------------------------------
# THREAD DE RECECAO (APENAS DEPOIS DO LOGIN)
# ---------------------------------------------------------------
def receiver_loop(sock: socket.socket):
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                print("\n[INFO] Ligacao fechada pelo servidor.")
                break
            msg = data.decode("utf-8", errors="ignore")
            print(msg, end="")
    except Exception as e:
        print(f"\n[ERRO] Receiver: {e}")
    finally:
        try:
            sock.close()
        except Exception:
            pass


# ---------------------------------------------------------------
# FUNCOES DE PROTOCOLO (REGISTER / LOGIN) - SINCRONAS
# ---------------------------------------------------------------
def register_and_wait_response(sock: socket.socket, username: str):
    """
    Envia REGISTER e espera 1 linha de resposta (OK ou ERR).
    """
    pub_pem = load_public_key_pem(username)

    # Converter PEM -> objeto -> DER (para mandar em base64)
    public_key = serialization.load_pem_public_key(pub_pem)
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    b64_pk = base64.b64encode(der_bytes).decode("utf-8")

    wire = f"REGISTER {username} {b64_pk}\n"
    sock.sendall(wire.encode("utf-8"))

    # Esperar resposta do servidor
    data = sock.recv(4096)
    if not data:
        print("[ERRO] Servidor fechou a ligacao durante REGISTER.")
        return False

    resp = data.decode("utf-8", errors="ignore").strip()
    print(resp)
    return resp.startswith("OK")


def perform_login(sock: socket.socket, username: str):
    """
    Protocolo de login (TOTALMENTE SINCRONO):
      1) enviar: LOGIN <username>
      2) receber: NONCE <nonce_base64>
      3) assinar nonce com chave privada RSA
      4) enviar: LOGIN_SIG <username> <signature_base64>
      5) receber: OK LOGIN (ou ERR ...)
    """
    # 1) Pedir login
    sock.sendall(f"LOGIN {username}\n".encode("utf-8"))

    # 2) Receber NONCE
    data = sock.recv(4096)
    if not data:
        print("[ERRO] Servidor fechou a ligacao durante LOGIN.")
        return False

    line = data.decode("utf-8", errors="ignore").strip()
    print(line)  # para veres o NONCE no ecrã

    if not line.startswith("NONCE "):
        print(f"[ERRO] Esperava NONCE, recebi: {line}")
        return False

    b64_nonce = line[len("NONCE ") :].strip()
    try:
        nonce = base64.b64decode(b64_nonce.encode("utf-8"), validate=True)
    except Exception:
        print("[ERRO] NONCE recebido nao e base64 valido.")
        return False

    # 3) Assinar nonce
    private_key = load_private_key(username)
    signature = private_key.sign(
        nonce,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    b64_sig = base64.b64encode(signature).decode("utf-8")

    # 4) Enviar assinatura
    wire = f"LOGIN_SIG {username} {b64_sig}\n"
    sock.sendall(wire.encode("utf-8"))

    # 5) Ler resposta do servidor (OK LOGIN ou ERR ...)
    data = sock.recv(4096)
    if not data:
        print("[ERRO] Servidor fechou a ligacao depois de LOGIN_SIG.")
        return False

    resp = data.decode("utf-8", errors="ignore").strip()
    print(resp)
    if resp.startswith("OK LOGIN"):
        return True
    return False


# ---------------------------------------------------------------
# MAIN CLIENT
# ---------------------------------------------------------------
def main():
    print(f"[INFO] A ligar ao servidor em {HOST}:{PORT}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((HOST, PORT))
    except Exception as e:
        print(f"[ERRO] Nao foi possivel ligar ao servidor: {e}")
        return

    # Mensagem inicial do servidor (opcional)
    data = sock.recv(4096)
    if data:
        print(data.decode("utf-8", errors="ignore"), end="")

    username = input("Escolhe um username (identidade local): ").strip()
    if not username:
        print("[ERRO] Username vazio.")
        sock.close()
        return

    # Garante que temos par de chaves RSA para este username
    ensure_keys_exist(username)

    # -----------------------------------------------------------
    # FASE 1: REGISTO / LOGIN (SEM THREAD DE RECECAO)
    # -----------------------------------------------------------
    authenticated = False

    print("Comandos (antes do LOGIN):")
    print("  /register  -> registar username + chave publica no servidor")
    print("  /login     -> autenticar com assinatura de nonce")
    print("  /quit      -> sair")
    print("-----------------------------------------------------")

    while not authenticated:
        try:
            line = input("> ")
        except EOFError:
            line = "/quit"

        line = line.strip()
        if not line:
            continue

        if line == "/register":
            ok = register_and_wait_response(sock, username)
            if not ok:
                print("[INFO] Podes tentar /register outra vez ou /login se ja estiver registado.")
            continue

        if line == "/login":
            ok = perform_login(sock, username)
            if ok:
                authenticated = True
                break
            else:
                print("[ERRO] LOGIN falhou. Tenta outra vez.")
            continue

        if line == "/quit":
            try:
                sock.sendall(b"QUIT\n")
            except Exception:
                pass
            sock.close()
            print("[INFO] Cliente terminado.")
            return

        print("Comandos validos nesta fase: /register, /login, /quit")

    # -----------------------------------------------------------
    # FASE 2: CHAT (APOS LOGIN) - AGORA COM THREAD DE RECECAO
    # -----------------------------------------------------------
    print("-----------------------------------------------------")
    print("[INFO] Autenticado! Agora podes usar o chat.")
    print("Comandos (chat):")
    print("  /to <dest> <mensagem>  -> enviar mensagem para outro utilizador autenticado")
    print("  /list                  -> listar utilizadores online")
    print("  /quit                  -> sair")
    print("-----------------------------------------------------")

    # Lanca thread de rececao
    t = threading.Thread(target=receiver_loop, args=(sock,), daemon=True)
    t.start()

    try:
        while True:
            try:
                line = input("> ")
            except EOFError:
                line = "/quit"

            line = line.strip()
            if not line:
                continue

            if line == "/list":
                try:
                    sock.sendall(b"LIST\n")
                except Exception as e:
                    print(f"[ERRO] Nao foi possivel enviar LIST: {e}")
                continue

            if line.startswith("/to "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    print("Uso: /to <dest> <mensagem>")
                    continue
                _, dest, msg = parts
                wire = f"TO {dest} {msg}\n"
                try:
                    sock.sendall(wire.encode("utf-8"))
                except Exception as e:
                    print(f"[ERRO] Nao foi possivel enviar TO: {e}")
                continue

            if line == "/quit":
                try:
                    sock.sendall(b"QUIT\n")
                except Exception:
                    pass
                break

            print("Comando desconhecido. Use /to, /list, /quit")

    except KeyboardInterrupt:
        print("\n[INFO] Interrompido pelo utilizador (Ctrl+C).")
        try:
            sock.sendall(b"QUIT\n")
        except Exception:
            pass

    finally:
        try:
            sock.close()
        except Exception:
            pass
        print("[INFO] Cliente terminado.")
        sys.exit(0)


if __name__ == "__main__":
    main()
