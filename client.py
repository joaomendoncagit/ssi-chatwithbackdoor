#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ===============================================================
# CHATWITHBACKDOOR - CLIENTE V2
# ===============================================================
# Funcionalidades:
#   - Gera par de chaves RSA localmente (se ainda nao existir)
#   - REGISTO / LOGIN (assinatura de nonce) - SINCRONO
#   - Diretoria de chaves publicas: /getpk <user> -> GET_PK
#   - Diffie-Hellman efemero entre clientes:
#        /dh_start <user> -> DH_INIT / DH_REPLY
#   - Calcula:
#        Z (segredo partilhado)
#        K_enc = SHA256("enc" || Z)
#        K_mac = SHA256(K_enc)
#     e mostra no terminal para debug.
#
#   Nesta versao, as mensagens /to ainda vao em claro.
#   As chaves de sessao vao ser usadas para cifrar + HMAC
#   na proxima etapa (com backdoor).
# ===============================================================

import socket
import threading
import sys
import os
import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa, padding, x25519
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

    with open(priv_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

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
# ESTADO DH / CHAVES DE SESSAO
# ---------------------------------------------------------------
# peer -> {
#   "dh_priv": X25519PrivateKey,
#   "shared": bytes or None,
#   "k_enc": bytes or None,
#   "k_mac": bytes or None,
# }
dh_sessions = {}
dh_lock = threading.Lock()

# (Opcional) Tabela de chaves publicas de outros utilizadores (RSA)
peer_pubkeys = {}
peer_pk_lock = threading.Lock()


def derive_session_keys(shared: bytes):
    """
    Dado Z (segredo partilhado do DH), deriva:
      K_enc = SHA256("enc" || Z)
      K_mac = SHA256(K_enc)
    """
    k_enc = hashlib.sha256(b"enc" + shared).digest()
    k_mac = hashlib.sha256(k_enc).digest()
    return k_enc, k_mac


# ---------------------------------------------------------------
# THREAD DE RECECAO (CHAT + PK + DH)
# ---------------------------------------------------------------
def handle_server_line(line: str):
    """
    Processa uma unica linha vinda do servidor.
    Algumas linhas sao so impressas, outras mexem no estado DH.
    """
    line = line.strip()
    if not line:
        return

    # PK <username> <b64_der>
    if line.startswith("PK "):
        parts = line.split(" ", 2)
        if len(parts) < 3:
            print(f"[SERVIDOR] Linha PK mal formada: {line}")
            return
        _, user, b64_pk = parts
        try:
            der = base64.b64decode(b64_pk.encode("utf-8"), validate=True)
        except Exception:
            print(f"[SERVIDOR] PK de {user} tem base64 invalido.")
            return
        with peer_pk_lock:
            peer_pubkeys[user] = der
        print(f"[INFO] Chave publica de {user} recebida e guardada ({len(der)} bytes DER).")
        return

    # DH_INIT_FROM <orig> <b64_dh_pub>
    if line.startswith("DH_INIT_FROM "):
        parts = line.split(" ", 2)
        if len(parts) < 3:
            print(f"[SERVIDOR] Linha DH_INIT_FROM mal formada: {line}")
            return
        _, orig, b64_dh_pub = parts
        try:
            peer_pub = base64.b64decode(b64_dh_pub.encode("utf-8"), validate=True)
        except Exception:
            print(f"[DH] DH_INIT_FROM de {orig} com base64 invalido.")
            return

        try:
            peer_pub_key = x25519.X25519PublicKey.from_public_bytes(peer_pub)
        except Exception:
            print(f"[DH] Public key DH_INIT_FROM de {orig} invalida.")
            return

        # Gerar DH efemero local (lado receptor)
        priv = x25519.X25519PrivateKey.generate()
        shared = priv.exchange(peer_pub_key)
        k_enc, k_mac = derive_session_keys(shared)

        with dh_lock:
            dh_sessions[orig] = {
                "dh_priv": priv,
                "shared": shared,
                "k_enc": k_enc,
                "k_mac": k_mac,
            }

        # Enviar DH_REPLY para o originador
        my_pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        b64_my_pub = base64.b64encode(my_pub).decode("utf-8")

        # O socket em si e gerido noutra funcao, aqui so imprimimos instrucoes;
        # o envio real e feito na receiver_loop (onde temos acesso ao socket)
        print(f"[DH] Recebido DH_INIT_FROM {orig}. Sessao DH criada.")
        print(f"[DH]   Z (primeiros 16 hex): {shared.hex()[:32]}")
        print(f"[DH]   K_enc (primeiros 16 hex): {k_enc.hex()[:32]}")
        print(f"[DH]   K_mac (primeiros 16 hex): {k_mac.hex()[:32]}")
        # Retornamos um "comando interno" para dizer ao receiver_loop para mandar DH_REPLY.
        return ("SEND_DH_REPLY", orig, b64_my_pub)

    # DH_REPLY_FROM <orig> <b64_dh_pub>
    if line.startswith("DH_REPLY_FROM "):
        parts = line.split(" ", 2)
        if len(parts) < 3:
            print(f"[SERVIDOR] Linha DH_REPLY_FROM mal formada: {line}")
            return
        _, orig, b64_dh_pub = parts
        try:
            peer_pub = base64.b64decode(b64_dh_pub.encode("utf-8"), validate=True)
        except Exception:
            print(f"[DH] DH_REPLY_FROM de {orig} com base64 invalido.")
            return

        try:
            peer_pub_key = x25519.X25519PublicKey.from_public_bytes(peer_pub)
        except Exception:
            print(f"[DH] Public key DH_REPLY_FROM de {orig} invalida.")
            return

        with dh_lock:
            state = dh_sessions.get(orig)

        if state is None:
            print(f"[DH] Recebido DH_REPLY_FROM {orig}, mas nao ha DH_INIT em curso.")
            return

        priv = state["dh_priv"]
        shared = priv.exchange(peer_pub_key)
        k_enc, k_mac = derive_session_keys(shared)

        with dh_lock:
            dh_sessions[orig]["shared"] = shared
            dh_sessions[orig]["k_enc"] = k_enc
            dh_sessions[orig]["k_mac"] = k_mac

        print(f"[DH] Sessao DH com {orig} COMPLETA (lado iniciador).")
        print(f"[DH]   Z (primeiros 16 hex): {shared.hex()[:32]}")
        print(f"[DH]   K_enc (primeiros 16 hex): {k_enc.hex()[:32]}")
        print(f"[DH]   K_mac (primeiros 16 hex): {k_mac.hex()[:32]}")
        return

    # Por omissao, e uma linha "normal" (chat / USERS / ERR / etc.)
    print(line)


def receiver_loop(sock: socket.socket):
    """
    Recebe dados do servidor, separa em linhas, e chama handle_server_line.
    Se handle_server_line devolver ("SEND_DH_REPLY", dest, b64_pub),
    entao aqui e que enviamos o comando DH_REPLY dest b64_pub.
    """
    try:
        buffer = ""
        while True:
            data = sock.recv(4096)
            if not data:
                print("\n[INFO] Ligacao fechada pelo servidor.")
                break
            buffer += data.decode("utf-8", errors="ignore")

            # Processar linha a linha
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                res = handle_server_line(line)
                # Se handle_server_line devolveu um comando interno
                if isinstance(res, tuple) and res and res[0] == "SEND_DH_REPLY":
                    _, dest, b64_my_pub = res
                    wire = f"DH_REPLY {dest} {b64_my_pub}\n"
                    try:
                        sock.sendall(wire.encode("utf-8"))
                    except Exception as e:
                        print(f"[ERRO] Nao foi possivel enviar DH_REPLY para {dest}: {e}")

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

    public_key = serialization.load_pem_public_key(pub_pem)
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    b64_pk = base64.b64encode(der_bytes).decode("utf-8")

    wire = f"REGISTER {username} {b64_pk}\n"
    sock.sendall(wire.encode("utf-8"))

    data = sock.recv(4096)
    if not data:
        print("[ERRO] Servidor fechou a ligacao durante REGISTER.")
        return False

    resp = data.decode("utf-8", errors="ignore").strip()
    print(resp)
    return resp.startswith("OK")


def perform_login(sock: socket.socket, username: str):
    """
    Protocolo de login (TOTALMENTE SINCRONO).
    """
    sock.sendall(f"LOGIN {username}\n".encode("utf-8"))

    data = sock.recv(4096)
    if not data:
        print("[ERRO] Servidor fechou a ligacao durante LOGIN.")
        return False

    line = data.decode("utf-8", errors="ignore").strip()
    print(line)

    if not line.startswith("NONCE "):
        print(f"[ERRO] Esperava NONCE, recebi: {line}")
        return False

    b64_nonce = line[len("NONCE ") :].strip()
    try:
        nonce = base64.b64decode(b64_nonce.encode("utf-8"), validate=True)
    except Exception:
        print("[ERRO] NONCE recebido nao e base64 valido.")
        return False

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

    wire = f"LOGIN_SIG {username} {b64_sig}\n"
    sock.sendall(wire.encode("utf-8"))

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
# COMANDOS DH DO LADO DO UTILIZADOR
# ---------------------------------------------------------------
def start_dh_with_peer(sock: socket.socket, peer: str):
    """
    Inicia DH efemero com outro utilizador:
      - gera par X25519 (dh_priv, dh_pub)
      - envia DH_INIT <peer> <b64_dh_pub>
      - guarda dh_priv em dh_sessions[peer]
    A resposta DH_REPLY_FROM sera tratada na receiver_loop.
    """
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    b64_pub = base64.b64encode(pub).decode("utf-8")

    with dh_lock:
        dh_sessions[peer] = {
            "dh_priv": priv,
            "shared": None,
            "k_enc": None,
            "k_mac": None,
        }

    wire = f"DH_INIT {peer} {b64_pub}\n"
    try:
        sock.sendall(wire.encode("utf-8"))
        print(f"[DH] Iniciado DH com {peer}. A aguardar DH_REPLY_FROM {peer}...")
    except Exception as e:
        print(f"[ERRO] Nao foi possivel enviar DH_INIT para {peer}: {e}")


def show_dh_sessions():
    """
    Mostra resumo das sessoes DH conhecidas (Z, K_enc, K_mac).
    """
    with dh_lock:
        if not dh_sessions:
            print("[DH] Nao ha sessoes DH guardadas.")
            return
        for peer, st in dh_sessions.items():
            print(f"[DH] Sessao com {peer}:")
            if st["shared"] is None:
                print("      shared = None (ainda em curso?)")
            else:
                print(f"      Z     (16 hex): {st['shared'].hex()[:32]}")
            if st["k_enc"] is None:
                print("      K_enc = None")
            else:
                print(f"      K_enc (16 hex): {st['k_enc'].hex()[:32]}")
            if st["k_mac"] is None:
                print("      K_mac = None")
            else:
                print(f"      K_mac (16 hex): {st['k_mac'].hex()[:32]}")


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

    data = sock.recv(4096)
    if data:
        print(data.decode("utf-8", errors="ignore"), end="")

    username = input("Escolhe um username (identidade local): ").strip()
    if not username:
        print("[ERRO] Username vazio.")
        sock.close()
        return

    ensure_keys_exist(username)

    # FASE 1: REGISTO / LOGIN (SEM THREAD DE RECECAO)
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

    # FASE 2: CHAT + DH (COM THREAD DE RECECAO)
    print("-----------------------------------------------------")
    print("[INFO] Autenticado! Agora podes usar o chat e DH.")
    print("Comandos (chat + DH):")
    print("  /to <dest> <mensagem>  -> enviar mensagem para outro utilizador autenticado")
    print("  /list                  -> listar utilizadores online")
    print("  /getpk <user>          -> pedir chave publica RSA de <user>")
    print("  /dh_start <user>       -> iniciar DH efemero com <user>")
    print("  /dh_show               -> mostrar sessoes DH e chaves derivadas")
    print("  /quit                  -> sair")
    print("-----------------------------------------------------")

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

            if line.startswith("/getpk "):
                parts = line.split(" ", 1)
                if len(parts) < 2:
                    print("Uso: /getpk <user>")
                    continue
                _, user = parts
                wire = f"GET_PK {user}\n"
                try:
                    sock.sendall(wire.encode("utf-8"))
                except Exception as e:
                    print(f"[ERRO] Nao foi possivel enviar GET_PK: {e}")
                continue

            if line.startswith("/dh_start "):
                parts = line.split(" ", 1)
                if len(parts) < 2:
                    print("Uso: /dh_start <user>")
                    continue
                _, peer = parts
                start_dh_with_peer(sock, peer)
                continue

            if line == "/dh_show":
                show_dh_sessions()
                continue

            if line == "/quit":
                try:
                    sock.sendall(b"QUIT\n")
                except Exception:
                    pass
                break

            print("Comando desconhecido. Use /to, /list, /getpk, /dh_start, /dh_show, /quit")

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
