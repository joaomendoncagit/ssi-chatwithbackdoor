"""
ChatWithBackdoor - Cliente
==========================
Sistema de chat com cifragem AES-CBC, autenticação HMAC e backdoor no servidor.

Funcionalidades principais:
  - Par de chaves RSA local por utilizador
  - A chave privada RSA é **encriptada em disco** com password
    (BestAvailableEncryption) e só é desencriptada em memória
    quando o utilizador faz LOGIN com essa password.
  - REGISTER:
      REGISTER <username> <password> <pubkey_der_base64>
  - LOGIN (2 fases):
      LOGIN <username> <password>    -> servidor manda NONCE base64
      LOGIN_SIG <username> <sig_b64> -> assinatura RSA-PSS do NONCE
  - DH efémero (X25519) entre clientes
  - Chaves de sessão: K_enc (AES-128), K_mac (HMAC-SHA256) derivadas do segredo DH
  - Mensagens cifradas AES-CBC + HMAC-SHA256
  - Backdoor no servidor via "blob":
      blob   = AES-ECB_Encrypt(K_SERVER, K_enc)
      IV     = primeiros 16 bytes de blob
      tag    = HMAC(K_mac, header || blob || IV || C)
  - Assinatura digital opcional em /send_signed
  - Comando /history para pedir histórico ao servidor
"""

import socket
import threading
import sys
import os
import base64
import hashlib
import hmac
import getpass

from cryptography.hazmat.primitives.asymmetric import rsa, padding, x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympadding

HOST = "127.0.0.1"
PORT = 5000

# Tem de ser igual ao do servidor para a backdoor funcionar.
K_SERVER = b"0123456789abcdef"  # 16 bytes

# ---------------------------------------------------------------
# PARÂMETROS GLOBAIS DO SCHNORR (grupo mod p)
# ---------------------------------------------------------------
P_SCHNORR = 182320749560328666954403774845227332467884691352689089204930399627621149290203
Q_SCHNORR = 91160374780164333477201887422613666233942345676344544602465199813810574645101
G_SCHNORR = 3


# Chave privada RSA do utilizador desencriptada em memória
# (preenchida no LOGIN, usada em /send_signed)
user_private_key = None
user_priv_lock = threading.Lock()


# ---------------------------------------------------------------
# AUXILIARES CRIPTO
# ---------------------------------------------------------------
def aes_encrypt_ecb(key: bytes, block: bytes) -> bytes:
    """
    Cifra um bloco com AES-ECB.
    
    Input: key (16 bytes), block (16 bytes)
    Output: ciphertext (16 bytes)
    """
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(block) + enc.finalize()


def aes_decrypt_ecb(key: bytes, block: bytes) -> bytes:
    """
    Decifra um bloco com AES-ECB.
    
    Input: key (16 bytes), block (16 bytes)
    Output: plaintext (16 bytes)
    """
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    dec = cipher.decryptor()
    return dec.update(block) + dec.finalize()


def aes_encrypt_cbc(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """
    Cifra dados com AES-CBC e padding PKCS7.
    
    Input: key (16 bytes), iv (16 bytes), plaintext (bytes)
    Output: ciphertext (bytes, múltiplo de 16)
    """
    padder = sympadding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def aes_decrypt_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decifra dados com AES-CBC e remove padding PKCS7.
    
    Input: key (16 bytes), iv (16 bytes), ciphertext (bytes)
    Output: plaintext (bytes)
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


# ---------------------------------------------------------------
# GESTAO DE CHAVES RSA NO CLIENTE
# ---------------------------------------------------------------
def get_key_filenames(username: str):
    """
    Retorna o nome dos ficheiros de chaves RSA para um utilizador.
    
    Input: username (str)
    Output: (priv_file, pub_file) (tuple of str)
    """
    priv_file = f"{username}_priv.pem"
    pub_file = f"{username}_pub.pem"
    return priv_file, pub_file


def keys_exist(username: str) -> bool:
    """
    Verifica se chaves RSA existem; se não, gera-as.
    
    Input: username (str)
    Output: None
    """
    priv_file, pub_file = get_key_filenames(username)
    return os.path.exists(priv_file) and os.path.exists(pub_file)


def generate_rsa_keypair(username: str, password: str):
    """
    Gera um par de chaves RSA e guarda:
      - chave privada encriptada com a password (PKCS8 + BestAvailableEncryption)
      - chave publica em claro (PEM)
    """
    priv_file, pub_file = get_key_filenames(username)

    print(f"[INFO] A gerar par de chaves RSA para '{username}'...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    pw_bytes = password.encode("utf-8")

    # Chave privada fica protegida com password no disco
    with open(priv_file, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(pw_bytes),
            )
        )

    # Chave publica em PEM, sem password
    with open(pub_file, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print(f"[INFO] Chaves guardadas em {priv_file} (encriptada) e {pub_file}")


def load_private_key(username: str, password: str):
    """
    Carrega a chave privada encriptada com a password dada.
    Só existe em memória enquanto o programa corre.
    """
    priv_file, _ = get_key_filenames(username)
    with open(priv_file, "rb") as f:
        data = f.read()

    pw_bytes = password.encode("utf-8")
    return serialization.load_pem_private_key(data, password=pw_bytes)


def load_public_key_pem(username: str) -> bytes:
    """
    Carrega a chave publica PEM (não encriptada).
    """
    _, pub_file = get_key_filenames(username)
    with open(pub_file, "rb") as f:
        return f.read()

# ---------------------------------------------------------------
# SCHNORR: derivação de segredo x a partir de (username, password)
# ---------------------------------------------------------------
def schnorr_derive_secret_x(username: str, password: str) -> int:
    """
    Deriva o segredo Schnorr x = H(username_normalizado || ":" || password) mod Q_SCHNORR.
    """
    username_norm = username.strip().lower()
    data = (username_norm + ":" + password).encode("utf-8")
    h = hashlib.sha256(data).digest()
    x = int.from_bytes(h, "big") % Q_SCHNORR
    if x == 0:
        x = 1
    return x


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
    Deriva chaves de sessão a partir do segredo DH.
    
    Input: shared (32 bytes - segredo X25519)
    Output: (k_enc, k_mac) - (16 bytes, 32 bytes)
    
    Processo:
      full = SHA256("enc" || shared)
      k_enc = full[:16]  (AES-128)
      k_mac = SHA256(k_enc)
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
    Processa uma linha recebida do servidor.
    
    Input: line (str) - linha do protocolo
    Output: None ou tuple para acções adicionais
    
    Tipos de mensagens processadas:
      - MSG_FROM: mensagem cifrada de outro utilizador
      - PK: chave pública RSA de utilizador
      - DH_INIT_FROM: pedido DH de outro utilizador
      - DH_REPLY_FROM: resposta DH de outro utilizador
      - Outras: mensagens de sistema/chat
    """
    line = line.strip()
    if not line:
        return

    # MSG_FROM orig b64_header b64_blob b64_iv b64_cipher b64_tag
    if line.startswith("MSG_FROM "):
        parts = line.split(" ", 6)
        if len(parts) < 7:
            print(f"[SERVIDOR] Linha MSG_FROM mal formada: {line}")
            return
        _, orig, b64_header, b64_blob, b64_iv, b64_cipher, b64_tag = parts

        try:
            header = base64.b64decode(b64_header.encode("utf-8"), validate=True)
            blob = base64.b64decode(b64_blob.encode("utf-8"), validate=True)
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

        # Verificar integridade (HMAC) antes de decifrar
        calc_tag = hmac_sha256(k_mac, header + blob + iv + cipher)
        if not hmac.compare_digest(calc_tag, tag):
            print(f"[MSG] HMAC invalido para mensagem de {orig} (mensagem corrompida/alterada).")
            return

        # Decifrar
        try:
            plaintext = aes_decrypt_cbc(k_enc, iv, cipher)
        except Exception:
            print(f"[MSG] Erro ao decifrar mensagem de {orig}.")
            return

        try:
            text = plaintext.decode("utf-8")
        except Exception:
            text = plaintext.decode("utf-8", errors="replace")

        # --- Verificar se vem com assinatura digital embedada ---
        if "||SIG||" in text:
            # Formato: msg || "||SIG||" || base64(signature)
            try:
                msg_part, sig_b64 = text.rsplit("||SIG||", 1)
            except ValueError:
                print(f"FROM {orig} [cifrado+HMAC]: {text}")
                return

            msg_bytes = msg_part.encode("utf-8")
            try:
                sig_bytes = base64.b64decode(sig_b64.encode("utf-8"), validate=True)
            except Exception:
                print(f"FROM {orig} [cifrado+HMAC+ASSIN_MALFORMADA]: {msg_part}")
                return

            # Ir buscar a chave publica do 'orig' previamente guardada pelo /getpk
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

            # Verificar assinatura RSA-PSS da mensagem original
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
        # Guardar chave publica (DER) para verificar assinaturas futuras
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

        # Lado que responde gera a sua chave DH e calcula segredo partilhado
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
        # Devolver instrução para enviar DH_REPLY de volta ao servidor
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

        # Lado que iniciou o DH completa o segredo partilhado
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

    # Linha normal (chat / USERS / ERR / HISTORY / etc.)
    print(line)


def receiver_loop(sock: socket.socket):
    """
    Thread que fica a ler continuamente do socket, linha a linha,
    e delega para handle_server_line.
    """
    try:
        buffer = ""
        while True:
            data = sock.recv(4096)
            if not data:
                print("\n[INFO] Ligacao fechada pelo servidor.")
                break
            buffer += data.decode("utf-8", errors="ignore")

            # Processar linha a linha (protocolo baseado em \n)
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                res = handle_server_line(line)
                # No caso de DH_INIT_FROM, handle_server_line devolve SEND_DH_REPLY
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
# REGISTER / LOGIN (SINCRONOS) COM PASSWORD + NONCE
# ---------------------------------------------------------------
def register_and_wait_response(sock: socket.socket, username: str, password: str):
    """
    Garante que existem chaves locais (gerando par RSA encriptado se preciso),
    depois envia:
      REGISTER <username> <password> <pubkey_der_base64>
    """
    # Garantir chaves locais (privada encriptada + publica)
    if not keys_exist(username):
        generate_rsa_keypair(username, password)
    else:
        print("[INFO] A usar chaves RSA locais ja existentes para este username.")

    # Converter a chave publica PEM local para DER base64 (para o servidor guardar)
    pub_pem = load_public_key_pem(username)

    public_key = serialization.load_pem_public_key(pub_pem)
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    b64_pk = base64.b64encode(der_bytes).decode("utf-8")

    # Schnorr: derivar x e calcular y = g^x mod p
    x = schnorr_derive_secret_x(username, password)
    y_int = pow(G_SCHNORR, x, P_SCHNORR)
    y_bytes = y_int.to_bytes((y_int.bit_length() + 7) // 8 or 1, "big")
    y_b64 = base64.b64encode(y_bytes).decode("utf-8")

    wire = f"REGISTER {username} {password} {b64_pk} {y_b64}\n"
    sock.sendall(wire.encode("utf-8"))

    data = sock.recv(4096)
    if not data:
        print("[ERRO] Servidor fechou a ligacao durante REGISTER.")
        return False

    resp = data.decode("utf-8", errors="ignore").strip()
    print(resp)
    return resp.startswith("OK")



def perform_login(sock: socket.socket, username: str, password: str):
    """
    LOGIN em duas fases:
      1) LOGIN <username> <password>  -> Servidor responde com NONCE ...
      2) LOGIN_SIG <username> <signature_base64> (assinatura do nonce)
         (para assinar, a chave privada é desencriptada com a mesma password)

    Se o LOGIN for bem sucedido, a chave privada RSA fica desencriptada
    em memória (user_private_key) enquanto o programa corre.
    """
    global user_private_key

    if not keys_exist(username):
        print(
            "[ERRO] Nao existem chaves RSA locais para este username.\n"
            "       Faz /register neste dispositivo primeiro para gerar as chaves."
        )
        return False

    # 1) username + password (verificação de password + nonce do lado do servidor)
    wire = f"LOGIN {username} {password}\n"
    sock.sendall(wire.encode("utf-8"))

    data = sock.recv(4096)
    if not data:
        print("[ERRO] Servidor fechou a ligacao durante LOGIN.")
        return False

    line = data.decode("utf-8", errors="ignore").strip()
    print(line)

    if not line.startswith("NONCE "):
        print(f"[ERRO] Esperava NONCE, recebi: {line}")
        return False

    b64_nonce = line[len("NONCE "):].strip()
    try:
        nonce = base64.b64decode(b64_nonce.encode("utf-8"), validate=True)
    except Exception:
        print("[ERRO] NONCE recebido nao e base64 valido.")
        return False

    # 2) Assinar nonce com chave privada RSA (desencriptando com a password)
    try:
        private_key = load_private_key(username, password)
    except Exception:
        print("[ERRO] Nao foi possivel desencriptar a chave privada com essa password.")
        return False

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
        # Guardar a chave privada em memoria para /send_signed
        with user_priv_lock:
            user_private_key = private_key
        return True

    return False

def perform_login_zkp(sock: socket.socket, username: str, password: str):
    """
    LOGIN via protocolo de conhecimento zero de Schnorr:
      1) Cliente deriva x a partir de (username, password).
      2) Escolhe r, calcula t = g^r mod p e envia:
           LOGIN_ZKP <username> <t_b64>
      3) Servidor responde com:
           ZKP_CHALLENGE <c_b64>
      4) Cliente calcula s = r + c*x mod Q_SCHNORR e envia:
           LOGIN_ZKP_RESP <username> <s_b64>
      5) Se a verificação no servidor passar, recebe "OK LOGIN_ZKP".
         Nesta altura também desencriptamos a chave privada RSA localmente
         com a mesma password (como no LOGIN normal).
    """
    global user_private_key

    if not keys_exist(username):
        print(
            "[ERRO] Nao existem chaves RSA locais para este username.\n"
            "       Faz /register neste dispositivo primeiro para gerar as chaves."
        )
        return False

    # Derivar segredo Schnorr x
    x = schnorr_derive_secret_x(username, password)

    # Escolher r aleatorio mod Q_SCHNORR e calcular t = g^r mod p
    r_bytes = os.urandom(32)
    r = int.from_bytes(r_bytes, "big") % Q_SCHNORR
    if r == 0:
        r = 1

    t_int = pow(G_SCHNORR, r, P_SCHNORR)
    t_bytes = t_int.to_bytes((t_int.bit_length() + 7) // 8 or 1, "big")
    t_b64 = base64.b64encode(t_bytes).decode("utf-8")

    # 1) Enviar commitment t
    wire = f"LOGIN_ZKP {username} {t_b64}\n"
    sock.sendall(wire.encode("utf-8"))

    # 2) Esperar desafio do servidor
    data = sock.recv(4096)
    if not data:
        print("[ERRO] Servidor fechou a ligacao durante LOGIN_ZKP.")
        return False

    line = data.decode("utf-8", errors="ignore").strip()
    print(line)

    if not line.startswith("ZKP_CHALLENGE "):
        print(f"[ERRO] Esperava ZKP_CHALLENGE, recebi: {line}")
        return False

    c_b64 = line[len("ZKP_CHALLENGE ") :].strip()
    try:
        c_bytes = base64.b64decode(c_b64.encode("utf-8"), validate=True)
        c_int = int.from_bytes(c_bytes, "big") % Q_SCHNORR
    except Exception:
        print("[ERRO] Desafio ZKP nao e base64 valido.")
        return False

    # 3) Calcular resposta s = r + c*x mod Q_SCHNORR
    s_int = (r + c_int * x) % Q_SCHNORR
    s_bytes = s_int.to_bytes((s_int.bit_length() + 7) // 8 or 1, "big")
    s_b64 = base64.b64encode(s_bytes).decode("utf-8")

    wire = f"LOGIN_ZKP_RESP {username} {s_b64}\n"
    sock.sendall(wire.encode("utf-8"))

    # 4) Ler resultado final do servidor
    data = sock.recv(4096)
    if not data:
        print("[ERRO] Servidor fechou a ligacao depois de LOGIN_ZKP_RESP.")
        return False

    resp = data.decode("utf-8", errors="ignore").strip()
    print(resp)
    if not resp.startswith("OK LOGIN_ZKP"):
        return False

    # Se chegou aqui, login ZKP passou -> desencriptar chave RSA localmente
    try:
        private_key = load_private_key(username, password)
    except Exception:
        print("[ERRO] Nao foi possivel desencriptar a chave privada com essa password.")
        return False

    with user_priv_lock:
        user_private_key = private_key

    return True


# ---------------------------------------------------------------
# COMANDOS DH DO UTILIZADOR
# ---------------------------------------------------------------
def start_dh_with_peer(sock: socket.socket, peer: str):
    """
    Inicia DH efémero com outro utilizador:
      DH_INIT <peer> <b64_dh_pub>
    """
    # Gera par de chaves X25519 efémeras (por sessão)
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
    Mostra as sessões DH e as chaves derivadas (debug).
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
# ENVIO SEGURO (CIFRA + HMAC + BACKDOOR COM BLOB)
# ---------------------------------------------------------------
def build_cipher_packet(my_username: str, dest: str, k_enc: bytes, k_mac: bytes, msg_bytes: bytes):
    """
    Constrói (b64_header, b64_blob, b64_iv, b64_cipher, b64_tag) prontos para enviar em MSG,
    com o backdoor embebido via 'blob':
      header = "orig->dest"
      blob   = AES-ECB(K_SERVER, K_enc)
      IV     = primeiros 16 bytes de blob
      tag    = HMAC(K_mac, header || blob || IV || C)
    """
    header = f"{my_username}->{dest}".encode("utf-8")

    # Backdoor: blob = AES-ECB(K_SERVER, K_enc), IV = primeiros 16 bytes de blob
    blob = aes_encrypt_ecb(K_SERVER, k_enc)
    iv = blob[:16]

    cipher = aes_encrypt_cbc(k_enc, iv, msg_bytes)
    tag = hmac_sha256(k_mac, header + blob + iv + cipher)

    b64_header = base64.b64encode(header).decode("utf-8")
    b64_blob = base64.b64encode(blob).decode("utf-8")
    b64_iv = base64.b64encode(iv).decode("utf-8")
    b64_cipher = base64.b64encode(cipher).decode("utf-8")
    b64_tag = base64.b64encode(tag).decode("utf-8")
    return b64_header, b64_blob, b64_iv, b64_cipher, b64_tag


def send_plaintext_message(sock: socket.socket, dest: str, msg_str: str):
    """
    Envia mensagem em texto limpo (INSEGURO - apenas para debug).
    
    Input: sock (socket), dest (str), msg_str (str)
    Output: None
    """
    wire = f"TO {dest} {msg_str}\n"
    try:
        sock.sendall(wire.encode("utf-8"))
        print(f"[MSG] Mensagem EM CLARO enviada para {dest}.")
    except Exception as e:
        print(f"[ERRO] Nao foi possivel enviar TO: {e}")


def send_secure_message(sock: socket.socket, my_username: str, dest: str, msg_str: str):
    """
    Envia mensagem cifrada com AES-CBC + HMAC (sem assinatura digital).
    
    Input: sock (socket), my_username (str), dest (str), msg_str (str)
    Output: None
    
    Requer sessão DH estabelecida com dest.
    """
    with dh_lock:
        st = dh_sessions.get(dest)

    if st is None or st["k_enc"] is None or st["k_mac"] is None:
        print(f"[MSG] Nao ha sessao DH estabelecida com {dest}. Usa /dh_start primeiro.")
        return

    k_enc = st["k_enc"]
    k_mac = st["k_mac"]

    plaintext = msg_str.encode("utf-8")
    b64_header, b64_blob, b64_iv, b64_cipher, b64_tag = build_cipher_packet(
        my_username, dest, k_enc, k_mac, plaintext
    )

    wire = f"MSG {dest} {b64_header} {b64_blob} {b64_iv} {b64_cipher} {b64_tag}\n"
    try:
        sock.sendall(wire.encode("utf-8"))
        print(f"[MSG] Mensagem cifrada enviada para {dest}.")
    except Exception as e:
        print(f"[ERRO] Nao foi possivel enviar MSG: {e}")


def send_signed_message(sock: socket.socket, my_username: str, dest: str, msg_str: str):
    """
    Envia mensagem cifrada + HMAC + assinatura digital RSA-PSS.
    
    Input: sock (socket), my_username (str), dest (str), msg_str (str)
    Output: None
    
    Formato da mensagem cifrada:
      plaintext = msg || "SIG" || base64(RSA_signature)
    
    Assinatura calculada sobre msg original (antes de cifrar).
    """
    global user_private_key

    with dh_lock:
        st = dh_sessions.get(dest)

    if st is None or st["k_enc"] is None or st["k_mac"] is None:
        print(f"[MSG] Nao ha sessao DH estabelecida com {dest}. Usa /dh_start primeiro.")
        return

    with user_priv_lock:
        priv = user_private_key

    if priv is None:
        print("[ERRO] Nao ha chave privada em memoria. Faz LOGIN outra vez.")
        return

    k_enc = st["k_enc"]
    k_mac = st["k_mac"]

    msg_bytes = msg_str.encode("utf-8")

    # Assinar mensagem original (antes de cifrar)
    signature = priv.sign(
        msg_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    b64_sig = base64.b64encode(signature).decode("utf-8")

    # Nota: evitar "||SIG||" literalmente no texto da mensagem.
    plaintext = (msg_str + "||SIG||" + b64_sig).encode("utf-8")

    b64_header, b64_blob, b64_iv, b64_cipher, b64_tag = build_cipher_packet(
        my_username, dest, k_enc, k_mac, plaintext
    )

    wire = f"MSG {dest} {b64_header} {b64_blob} {b64_iv} {b64_cipher} {b64_tag}\n"
    try:
        sock.sendall(wire.encode("utf-8"))
        print(f"[MSG] Mensagem CIFRADA + ASSINADA enviada para {dest}.")
    except Exception as e:
        print(f"[ERRO] Nao foi possivel enviar MSG assinada: {e}")


# ---------------------------------------------------------------
# MAIN CLIENT
# ---------------------------------------------------------------
def main():
    """
    Fluxo principal:
      1. Ligar ao servidor
      2. Escolher username
      3. Fase de REGISTER/LOGIN (com password)
      4. Fase de chat (/to, /send, /send_signed, /history, /dh_start, ...)
    """
    print(f"[INFO] A ligar ao servidor em {HOST}:{PORT}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((HOST, PORT))
    except Exception as e:
        print(f"[ERRO] Nao foi possivel ligar ao servidor: {e}")
        return

    # Mensagem de boas-vindas do servidor
    data = sock.recv(4096)
    if data:
        print(data.decode("utf-8", errors="ignore"), end="")

    username = input("Escolhe um username (identidade local): ").strip()
    if not username:
        print("[ERRO] Username vazio.")
        sock.close()
        return

    # FASE 1: REGISTO / LOGIN
    authenticated = False

    print("Comandos (antes do LOGIN):")
    print("  /register  -> registar username + password + chave publica no servidor")
    print("  /login     -> autenticar com username + password + assinatura de nonce")
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
            password = getpass.getpass("Escolhe uma password (sem espacos): ")
            if not password:
                print("[ERRO] Password vazia.")
                continue
            ok = register_and_wait_response(sock, username, password)
            if not ok:
                print("[INFO] Podes tentar /register outra vez ou /login se ja estiver registado.")
            continue

        if line == "/login":
            password = getpass.getpass("Password para ZKP: ")
            if not password:
                print("[ERRO] Password vazia.")
                continue
            ok = perform_login_zkp(sock, username, password)
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
    print("  /to <dest> <mensagem>                 -> enviar EM CLARO (SEM segurança)")
    print("  /send <dest> <mensagem>               -> enviar mensagem CIFRADA (AES-CBC + HMAC + backdoor)")
    print("  /send_signed <dest> <mensagem>        -> enviar mensagem CIFRADA + ASSINADA digitalmente")
    print("  /history <user> [opcoes]              -> historico (ex: -d 2024-12-06, -c 10, ...)")
    print("  /list                                 -> listar utilizadores online")
    print("  /getpk <user>                         -> pedir chave publica RSA de <user>")
    print("  /dh_start <user>                      -> iniciar DH efemero com <user>")
    print("  /dh_show                              -> mostrar sessoes DH e chaves derivadas")
    print("  /quit                                 -> sair")
    print("-----------------------------------------------------")

    # Thread que trata de receber dados do servidor em background
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

            # LIST
            if line == "/list":
                try:
                    sock.sendall(b"LIST\n")
                except Exception as e:
                    print(f"[ERRO] Nao foi possivel enviar LIST: {e}")
                continue

            # HISTORY (pedido de historico ao servidor)
            if line.startswith("/history"):
                tokens = line.split()
                if len(tokens) == 1:
                    print("Uso: /history <user> [opcoes]")
                    print("  Exemplos:")
                    print("    /history Bob")
                    print("    /history Bob -d 2024-12-06")
                    print("    /history Bob -c 10")
                    print("    /history Bob -d 2024-12-06 -c 20")
                    continue

                peer = tokens[1]
                extra_args = " ".join(tokens[2:]) if len(tokens) > 2 else ""
                if extra_args:
                    wire = f"HISTORY {peer} {extra_args}\n"
                else:
                    wire = f"HISTORY {peer}\n"

                try:
                    sock.sendall(wire.encode("utf-8"))
                except Exception as e:
                    print(f"[ERRO] Nao foi possivel enviar HISTORY: {e}")
                continue

            # /to -> mensagem em claro
            if line.startswith("/to "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    print("Uso: /to <dest> <mensagem>")
                    continue
                _, dest, msg = parts
                send_plaintext_message(sock, dest, msg)
                continue

            # /send -> enviar mensagem CIFRADA (AES-CBC + HMAC + backdoor)
            if line.startswith("/send "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    print("Uso: /send <dest> <mensagem>")
                    continue
                _, dest, msg = parts
                send_secure_message(sock, username, dest, msg)
                continue

            # /send_signed -> cifrado + assinatura digital RSA-PSS
            if line.startswith("/send_signed "):
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    print("Uso: /send_signed <dest> <mensagem>")
                    continue
                _, dest, msg = parts
                send_signed_message(sock, username, dest, msg)
                continue

            # GET_PK -> pedir chave publica RSA de outro utilizador
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

            # DH_START -> iniciar troca de chaves X25519
            if line.startswith("/dh_start "):
                parts = line.split(" ", 1)
                if len(parts) < 2:
                    print("Uso: /dh_start <user>")
                    continue
                _, peer = parts
                start_dh_with_peer(sock, peer)
                continue

            # DH_SHOW -> mostrar sessoes DH em memoria
            if line == "/dh_show":
                show_dh_sessions()
                continue

            # QUIT
            if line == "/quit":
                try:
                    sock.sendall(b"QUIT\n")
                except Exception:
                    pass
                break

            print(
                "Comando desconhecido. Use /to, /send, /send_signed, /history, /list, "
                "/getpk, /dh_start, /dh_show, /quit"
            )

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
