#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ===============================================================
# CHATWITHBACKDOOR - CLIENTE V4 (CIFRA + HMAC + BACKDOOR + ASSINATURA)
# ===============================================================
# Diferenças para V3.1:
#   - Novo comando: /send_signed <dest> <mensagem>
#   - Cada mensagem enviada com /send_signed é:
#        msg_bytes = mensagem em UTF-8
#        signature = Sign(sk.username, msg_bytes)  (RSA-PSS + SHA256)
#        b64_sig   = base64(signature)
#        plaintext = msg_bytes || b"||SIG||" || b64_sig
#     Este plaintext é então cifrado com AES-CBC (como antes) e autenticado com HMAC.
#   - Ao receber:
#       * Se plaintext contiver "||SIG||", tenta separar msg + assinatura,
#         obter pk do emissor (via /getpk <user>) e verificar a assinatura.
# ===============================================================

import socket
import threading
import sys
import os
import base64
import hashlib
import hmac

from cryptography.hazmat.primitives.asymmetric import rsa, padding, x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympadding

HOST = "127.0.0.1"
PORT = 5000

# Tem de ser igual ao do servidor para a backdoor funcionar.
K_SERVER = b"0123456789abcdef"  # 16 bytes


# ---------------------------------------------------------------
# AUXILIARES CRIPTO
# ---------------------------------------------------------------
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

# Tabela de chaves públicas de outros utilizadores (RSA, DER)
peer_pubkeys = {}
peer_pk_lock = threading.Lock()


def derive_session_keys(shared: bytes):
    """
    Dado Z (segredo partilhado do DH), deriva:
      full  = SHA256("enc" || Z)
      K_enc = full[:16]  (AES-128)
      K_mac = SHA256(K_enc)
    """
    full = hashlib.sha256(b"enc" + shared).digest()
    k_enc = full[:16]
    k_mac = hashlib.sha256(k_enc).digest()
    return k_enc, k_mac


# ---------------------------------------------------------------
# THREAD DE RECECAO (CHAT + PK + DH + MSG)
# ---------------------------------------------------------------
def handle_server_line(line: str):
    """
    Processa uma unica linha vinda do servidor.
    """
    line = line.strip()
    if not line:
        return

    # MSG_FROM orig b64_header b64_iv b64_cipher b64_tag
    if line.startswith("MSG_FROM "):
        parts = line.split(" ", 5)
        if len(parts) < 6:
            print(f"[SERVIDOR] Linha MSG_FROM mal formada: {line}")
            return
        _, orig, b64_header, b64_iv, b64_cipher, b64_tag = parts

        try:
            header = base64.b64decode(b64_header.encode("utf-8"), validate=True)
            iv = base64.b64decode(b64_iv.encode("utf-8"), validate=True)
            cipher = base64.b64decode(b64_cipher.encode("utf-8"), validate=True)
            tag = base64.b64decode(b64_tag.encode("utf-8"), validate=True)
        except Exception:
            print("[MSG] Campos base64 invalidos na mensagem recebida.")
            return

        with dh_lock:
            st = dh_sessions.get(orig)

        if st is None or st["k_enc"] is None or st["k_mac"] is None:
            print(f"[MSG] Nao ha sessao DH com {orig}. Nao consigo decifrar.")
            return

        k_enc = st["k_enc"]
        k_mac = st["k_mac"]

        calc_tag = hmac_sha256(k_mac, header + iv + cipher)
        if not hmac.compare_digest(calc_tag, tag):
            print(f"[MSG] HMAC invalido para mensagem de {orig} (mensagem corrompida/alterada).")
            return

        try:
            plaintext = aes_decrypt_cbc(k_enc, iv, cipher)
        except Exception:
            print(f"[MSG] Erro ao decifrar mensagem de {orig}.")
            return

        try:
            text = plaintext.decode("utf-8")
        except Exception:
            text = plaintext.decode("utf-8", errors="replace")

        # --- Verificar se vem com assinatura digital ---
        if "||SIG||" in text:
            try:
                msg_part, sig_b64 = text.rsplit("||SIG||", 1)
            except ValueError:
                # Marker estranho, tratamos como mensagem normal
                print(f"FROM {orig} [cifrado+HMAC]: {text}")
                return

            msg_bytes = msg_part.encode("utf-8")
            try:
                sig_bytes = base64.b64decode(sig_b64.encode("utf-8"), validate=True)
            except Exception:
                print(f"FROM {orig} [cifrado+HMAC+ASSIN_MALFORMADA]: {msg_part}")
                return

            # Tentar ir buscar chave publica do emissor
            with peer_pk_lock:
                der = peer_pubkeys.get(orig)

            if der is None:
                print(f"FROM {orig} [cifrado+HMAC][SEM PK PARA VERIFICAR]: {msg_part}")
                print(f"[INFO] Usa /getpk {orig} para poderes verificar assinaturas desse utilizador.")
                return

            try:
                pubkey = serialization.load_der_public_key(der)
            except Exception:
                print(f"FROM {orig} [cifrado+HMAC][PK INVALIDA LOCAL]: {msg_part}")
                return

            # Verificar assinatura RSA-PSS/SHA256
            try:
                pubkey.verify(
                    sig_bytes,
                    msg_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
                print(f"FROM {orig} [cifrado+HMAC+ASSIN_OK]: {msg_part}")
            except Exception:
                print(f"FROM {orig} [cifrado+HMAC+ASSIN_FAIL]: {msg_part}")
            return

        # Mensagem normal (sem assinatura embedada)
        print(f"FROM {orig} [cifrado+HMAC]: {text}")
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

        my_pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        b64_my_pub = base64.b64encode(my_pub).decode("utf-8")

        print(f"[DH] Recebido DH_INIT_FROM {orig}. Sessao DH criada.")
        print(f"[DH]   Z (primeiros 16 hex): {shared.hex()[:32]}")
        print(f"[DH]   K_enc (primeiros 16 hex): {k_enc.hex()[:32]}")
        print(f"[DH]   K_mac (primeiros 16 hex): {k_mac.hex()[:32]}")
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

    # Linha normal (chat / USERS / ERR / etc.)
    print(line)


def receiver_loop(sock: socket.socket):
    try:
        buffer = ""
        while True:
            data = sock.recv(4096)
            if not data:
                print("\n[INFO] Ligacao fechada pelo servidor.")
                break
            buffer += data.decode("utf-8", errors="ignore")

            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                res = handle_server_line(line)
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
# REGISTER / LOGIN (SINCRONOS)
# ---------------------------------------------------------------
def register_and_wait_response(sock: socket.socket, username: str):
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
# COMANDOS DH DO UTILIZADOR
# ---------------------------------------------------------------
def start_dh_with_peer(sock: socket.socket, peer: str):
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
# ENVIO SEGURO (CIFRA + HMAC + BACKDOOR)
# ---------------------------------------------------------------
def build_cipher_packet(my_username: str, dest: str, k_enc: bytes, k_mac: bytes, msg_bytes: bytes):
    """
    Constrói (b64_header, b64_iv, b64_cipher, b64_tag) prontos para enviar em MSG.
    """
    header = f"{my_username}->{dest}".encode("utf-8")

    # IV deterministicamente derivado de K_enc, com chave secreta K_SERVER
    iv = aes_encrypt_ecb(K_SERVER, k_enc)

    cipher = aes_encrypt_cbc(k_enc, iv, msg_bytes)
    tag = hmac_sha256(k_mac, header + iv + cipher)

    b64_header = base64.b64encode(header).decode("utf-8")
    b64_iv = base64.b64encode(iv).decode("utf-8")
    b64_cipher = base64.b64encode(cipher).decode("utf-8")
    b64_tag = base64.b64encode(tag).decode("utf-8")
    return b64_header, b64_iv, b64_cipher, b64_tag


def send_secure_message(sock: socket.socket, my_username: str, dest: str, msg_str: str):
    """
    Mensagem cifrada + HMAC, SEM assinatura digital embedada.
    """
    with dh_lock:
        st = dh_sessions.get(dest)

    if st is None or st["k_enc"] is None or st["k_mac"] is None:
        print(f"[MSG] Nao ha sessao DH estabelecida com {dest}. Usa /dh_start primeiro.")
        return

    k_enc = st["k_enc"]
    k_mac = st["k_mac"]

    plaintext = msg_str.encode("utf-8")
    b64_header, b64_iv, b64_cipher, b64_tag = build_cipher_packet(
        my_username, dest, k_enc, k_mac, plaintext
    )

    wire = f"MSG {dest} {b64_header} {b64_iv} {b64_cipher} {b64_tag}\n"
    try:
        sock.sendall(wire.encode("utf-8"))
        print(f"[MSG] Mensagem cifrada enviada para {dest}.")
    except Exception as e:
        print(f"[ERRO] Nao foi possivel enviar MSG: {e}")


def send_signed_message(sock: socket.socket, my_username: str, dest: str, msg_str: str):
    """
    Mensagem cifrada + HMAC + ASSINATURA DIGITAL (RSA-PSS):
      plaintext = msg || "||SIG||" || base64(signature)
    """
    with dh_lock:
        st = dh_sessions.get(dest)

    if st is None or st["k_enc"] is None or st["k_mac"] is None:
        print(f"[MSG] Nao ha sessao DH estabelecida com {dest}. Usa /dh_start primeiro.")
        return

    k_enc = st["k_enc"]
    k_mac = st["k_mac"]

    msg_bytes = msg_str.encode("utf-8")
    priv = load_private_key(my_username)

    signature = priv.sign(
        msg_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    b64_sig = base64.b64encode(signature).decode("utf-8")

    # Atenção: se a mensagem contiver literalmente "||SIG||", isto pode baralhar o parser.
    # Para o projeto chega bem evitar esse padrão no texto das mensagens.
    plaintext = (msg_str + "||SIG||" + b64_sig).encode("utf-8")

    b64_header, b64_iv, b64_cipher, b64_tag = build_cipher_packet(
        my_username, dest, k_enc, k_mac, plaintext
    )

    wire = f"MSG {dest} {b64_header} {b64_iv} {b64_cipher} {b64_tag}\n"
    try:
        sock.sendall(wire.encode("utf-8"))
        print(f"[MSG] Mensagem CIFRADA + ASSINADA enviada para {dest}.")
    except Exception as e:
        print(f"[ERRO] Nao foi possivel enviar MSG assinada: {e}")


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

    # FASE 1: REGISTO / LOGIN
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

    # FASE 2: CHAT + DH + MSG
    print("-----------------------------------------------------")
    print("[INFO] Autenticado! Agora podes usar o chat, DH e mensagens cifradas.")
    print("Comandos (chat + DH):")
    print("  /to <dest> <mensagem>         -> enviar mensagem CIFRADA (AES-CBC + HMAC + backdoor)")
    print("  /send <dest> <mensagem>       -> alias para /to (envio cifrado)")
    print("  /send_signed <dest> <mensagem>-> enviar mensagem CIFRADA + ASSINADA digitalmente")
    print("  /list                         -> listar utilizadores online")
    print("  /getpk <user>                 -> pedir chave publica RSA de <user> (para verificar assinaturas)")
    print("  /dh_start <user>              -> iniciar DH efemero com <user>")
    print("  /dh_show                      -> mostrar sessoes DH e chaves derivadas")
    print("  /quit                         -> sair")
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

            # /to -> envio cifrado
            if line.startswith("/to "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    print("Uso: /to <dest> <mensagem>")
                    continue
                _, dest, msg = parts
                send_secure_message(sock, username, dest, msg)
                continue

            # /send -> alias para envio cifrado
            if line.startswith("/send "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    print("Uso: /send <dest> <mensagem>")
                    continue
                _, dest, msg = parts
                send_secure_message(sock, username, dest, msg)
                continue

            # /send_signed -> cifrado + assinatura digital
            if line.startswith("/send_signed "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    print("Uso: /send_signed <dest> <mensagem>")
                    continue
                _, dest, msg = parts
                send_signed_message(sock, username, dest, msg)
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

            print("Comando desconhecido. Use /to, /send, /send_signed, /list, /getpk, /dh_start, /dh_show, /quit")

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
