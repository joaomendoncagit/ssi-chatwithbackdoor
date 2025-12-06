"""
ChatWithBackdoor - Testes Unitários
====================================
Testes automatizados com o objetivo de validar as funcionalidades criptográficas e protocolares do sistema.
"""

import unittest
import os
import base64
import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding, x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympadding


# Chave do servidor para testes (igual ao sistema)
K_SERVER = b"0123456789abcdef"


class TestCryptographicFunctions(unittest.TestCase):
    """
    Testes para funções criptográficas básicas.
    
    Valida: AES-ECB, AES-CBC, HMAC, padding
    """

    def setUp(self):
        """
        Preparação para cada teste.
        
        Input: None
        Output: None
        
        Cria chaves e dados de teste.
        """
        self.key_16 = os.urandom(16)
        self.key_32 = os.urandom(32)
        self.plaintext = b"Hello, World! This is a test message."
        self.iv = os.urandom(16)

    def test_aes_ecb_encrypt_decrypt(self):
        """
        Testa cifra e decifra AES-ECB.
        
        Input: bloco de 16 bytes
        Output: bloco original após encrypt/decrypt
        """
        block = b"1234567890123456"
        
        cipher = Cipher(algorithms.AES(self.key_16), modes.ECB())
        enc = cipher.encryptor()
        ciphertext = enc.update(block) + enc.finalize()
        
        dec = cipher.decryptor()
        plaintext = dec.update(ciphertext) + dec.finalize()
        
        self.assertEqual(plaintext, block)
        self.assertEqual(len(ciphertext), 16)

    def test_aes_cbc_with_padding(self):
        """
        Testa cifra e decifra AES-CBC com PKCS7 padding.
        
        Input: plaintext de tamanho arbitrário
        Output: plaintext original após encrypt/decrypt
        """
        # Encrypt
        padder = sympadding.PKCS7(128).padder()
        padded = padder.update(self.plaintext) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(self.key_16), modes.CBC(self.iv))
        enc = cipher.encryptor()
        ciphertext = enc.update(padded) + enc.finalize()
        
        # Decrypt
        dec = cipher.decryptor()
        padded_back = dec.update(ciphertext) + dec.finalize()
        
        unpadder = sympadding.PKCS7(128).unpadder()
        plaintext_back = unpadder.update(padded_back) + unpadder.finalize()
        
        self.assertEqual(plaintext_back, self.plaintext)
        self.assertEqual(len(ciphertext) % 16, 0)

    def test_hmac_sha256(self):
        """
        Testa o cálculo do HMAC-SHA256.
        
        Input: chave e dados
        Output: tag de 32 bytes, verificação de integridade
        """
        data = b"Test data for HMAC"
        tag = hmac.new(self.key_32, data, hashlib.sha256).digest()
        
        self.assertEqual(len(tag), 32)
        
        # Verificar que tags diferentes para dados diferentes
        tag2 = hmac.new(self.key_32, b"Different data", hashlib.sha256).digest()
        self.assertNotEqual(tag, tag2)
        
        # Verificar que a mesma entrada produz a mesma tag
        tag3 = hmac.new(self.key_32, data, hashlib.sha256).digest()
        self.assertEqual(tag, tag3)


class TestBackdoorMechanism(unittest.TestCase):
    """
    Testes para o mecanismo de backdoor.
    
    Valida: recuperação de K_enc via blob, derivação de K_mac
    """

    def test_backdoor_key_recovery(self):
        """
        Testa a recuperação da chave de cifra através do blob (backdoor).
        
        Input: K_enc original
        Output: K_enc recuperada = K_enc original
        
        Processo:
          1. Cliente: blob = AES-ECB(K_SERVER, K_enc)
          2. Servidor: K_enc_recovered = AES-ECB-Decrypt(K_SERVER, blob)
          3. Verificar K_enc == K_enc_recovered
        """
        k_enc = os.urandom(16)
        
        # Cliente cria blob (backdoor)
        cipher_enc = Cipher(algorithms.AES(K_SERVER), modes.ECB())
        encryptor = cipher_enc.encryptor()
        blob = encryptor.update(k_enc) + encryptor.finalize()
        
        # Servidor recupera K_enc do blob
        cipher_dec = Cipher(algorithms.AES(K_SERVER), modes.ECB())
        decryptor = cipher_dec.decryptor()
        k_enc_recovered = decryptor.update(blob) + decryptor.finalize()
        
        self.assertEqual(k_enc, k_enc_recovered)
        self.assertEqual(len(blob), 16)

    def test_backdoor_iv_from_blob(self):
        """
        Testa se o IV é derivado dos primeiros 16 bytes do blob.
        
        Input: K_enc
        Output: IV = blob[:16]
        """
        k_enc = os.urandom(16)
        
        cipher = Cipher(algorithms.AES(K_SERVER), modes.ECB())
        enc = cipher.encryptor()
        blob = enc.update(k_enc) + enc.finalize()
        
        iv = blob[:16]
        
        self.assertEqual(len(iv), 16)
        self.assertEqual(iv, blob)  # blob tem exatamente 16 bytes

    def test_kmac_derivation(self):
        """
        Testa a derivação de K_mac a partir de K_enc.
        
        Input: K_enc
        Output: K_mac = SHA256(K_enc)
        
        Verifica que K_mac tem 32 bytes e é determinística.
        """
        k_enc = os.urandom(16)
        
        k_mac = hashlib.sha256(k_enc).digest()
        
        self.assertEqual(len(k_mac), 32)
        
        # Verificar determinismo
        k_mac2 = hashlib.sha256(k_enc).digest()
        self.assertEqual(k_mac, k_mac2)


class TestRSAOperations(unittest.TestCase):
    """
    Testes para operações com RSA.
    
    Valida: geração de chaves, assinatura digital, verificação
    """

    def setUp(self):
        """
        Preparação para os testes.
        
        Input: None
        Output: None
        
        Gera par de chaves RSA para testes.
        """
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()

    def test_rsa_key_generation(self):
        """
        Testa a geração de par de chaves RSA.
        
        Input: None
        Output: chaves RSA válidas de 2048 bits
        """
        key_size = self.private_key.key_size
        self.assertEqual(key_size, 2048)

    def test_rsa_signature_verification(self):
        """
        Testa a assinatura e verificação digital com RSA-PSS.
        
        Input: mensagem
        Output: assinatura válida que pode ser verificada
        
        Protocolo usado no LOGIN do sistema.
        """
        message = b"Test message for signature"
        
        # Assinar
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        
        # Verificar - não deve lançar exceção
        try:
            self.public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            verified = True
        except Exception:
            verified = False
        
        self.assertTrue(verified)

    def test_rsa_signature_tampering_detection(self):
        """
        Testa a detecção de uma assinatura inválida (mensagem alterada).
        
        Input: mensagem + assinatura válida
        Output: verificação falha se mensagem for alterada
        """
        message = b"Original message"
        tampered_message = b"Tampered message"
        
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        
        # Verificar com mensagem alterada deve falhar
        with self.assertRaises(Exception):
            self.public_key.verify(
                signature,
                tampered_message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

    def test_rsa_serialization(self):
        """
        Testa a serialização de chaves RSA para PEM e DER.
        
        Input: chaves RSA
        Output: bytes PEM/DER que podem ser desserializados
        """
        # Serializar chave privada (PEM)
        priv_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        
        # Serializar chave pública (DER)
        pub_der = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        
        # Desserializar
        priv_loaded = serialization.load_pem_private_key(priv_pem, password=None)
        pub_loaded = serialization.load_der_public_key(pub_der)
        
        self.assertIsNotNone(priv_loaded)
        self.assertIsNotNone(pub_loaded)


class TestDiffieHellmanX25519(unittest.TestCase):
    """
    Testes para a troca de chaves Diffie-Hellman com X25519.
    
    Valida: geração de chaves, troca DH, derivação de segredo partilhado
    """

    def test_x25519_key_generation(self):
        """
        Testa geração de chaves X25519.
        
        Input: None
        Output: par de chaves X25519 válido
        """
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        
        self.assertEqual(len(pub_bytes), 32)

    def test_x25519_shared_secret(self):
        """
        Testa o cálculo de segredo partilhado DH.
        
        Input: chaves de Alice e Bob
        Output: segredo partilhado idêntico para ambos
        
        Simula protocolo DH_INIT/DH_REPLY do sistema.
        """
        # Alice gera par de chaves
        alice_private = x25519.X25519PrivateKey.generate()
        alice_public = alice_private.public_key()
        
        # Bob gera par de chaves
        bob_private = x25519.X25519PrivateKey.generate()
        bob_public = bob_private.public_key()
        
        # Alice calcula segredo partilhado
        alice_shared = alice_private.exchange(bob_public)
        
        # Bob calcula segredo partilhado
        bob_shared = bob_private.exchange(alice_public)
        
        # Segredos devem ser iguais
        self.assertEqual(alice_shared, bob_shared)
        self.assertEqual(len(alice_shared), 32)

    def test_session_key_derivation(self):
        """
        Testa derivação de chaves de sessão a partir do segredo DH.
        
        Input: shared_secret (32 bytes)
        Output: (K_enc=16 bytes, K_mac=32 bytes)
        
        Processo usado no sistema:
          full = SHA256("enc" || shared)
          K_enc = full[:16]
          K_mac = SHA256(K_enc)
        """
        shared_secret = os.urandom(32)
        
        # Derivar K_enc
        full = hashlib.sha256(b"enc" + shared_secret).digest()
        k_enc = full[:16]
        
        # Derivar K_mac
        k_mac = hashlib.sha256(k_enc).digest()
        
        self.assertEqual(len(k_enc), 16)
        self.assertEqual(len(k_mac), 32)
        
        # Verificar determinismo
        full2 = hashlib.sha256(b"enc" + shared_secret).digest()
        k_enc2 = full2[:16]
        self.assertEqual(k_enc, k_enc2)


class TestProtocolIntegration(unittest.TestCase):
    """
    Testes de integração do protocolo completo.
    
    Valida: fluxo completo de mensagem cifrada com backdoor
    """

    def test_full_message_encryption_with_backdoor(self):
        """
        Testa o fluxo completo: cifra -> backdoor -> decifra.
        
        Input: mensagem plaintext
        Output: mensagem recuperada (cliente e servidor)
        
        Simula:
          1. Cliente cifra com K_enc, embedando blob
          2. Servidor recupera K_enc do blob
          3. Servidor decifra mensagem
          4. Cliente destino decifra mensagem
        """
        # Setup: chaves de sessão (resultado de DH)
        k_enc = os.urandom(16)
        k_mac = hashlib.sha256(k_enc).digest()
        
        # Mensagem original
        message = b"Secret message from Alice to Bob"
        
        # CLIENTE: Construir pacote cifrado com backdoor
        header = b"alice->bob"
        
        # Backdoor: blob contém K_enc cifrada com K_SERVER
        cipher_blob = Cipher(algorithms.AES(K_SERVER), modes.ECB())
        enc_blob = cipher_blob.encryptor()
        blob = enc_blob.update(k_enc) + enc_blob.finalize()
        
        # IV derivado do blob
        iv = blob[:16]
        
        # Cifrar mensagem com AES-CBC
        padder = sympadding.PKCS7(128).padder()
        padded = padder.update(message) + padder.finalize()
        cipher_msg = Cipher(algorithms.AES(k_enc), modes.CBC(iv))
        enc_msg = cipher_msg.encryptor()
        ciphertext = enc_msg.update(padded) + enc_msg.finalize()
        
        # HMAC
        tag = hmac.new(k_mac, header + blob + iv + ciphertext, hashlib.sha256).digest()
        
        # SERVIDOR: Backdoor - recuperar K_enc
        cipher_server = Cipher(algorithms.AES(K_SERVER), modes.ECB())
        dec_server = cipher_server.decryptor()
        k_enc_recovered = dec_server.update(blob) + dec_server.finalize()
        
        self.assertEqual(k_enc, k_enc_recovered)
        
        # SERVIDOR: Derivar K_mac
        k_mac_server = hashlib.sha256(k_enc_recovered).digest()
        
        # SERVIDOR: Verificar HMAC
        tag_calc = hmac.new(k_mac_server, header + blob + iv + ciphertext, hashlib.sha256).digest()
        self.assertTrue(hmac.compare_digest(tag, tag_calc))
        
        # SERVIDOR: Decifrar mensagem
        cipher_dec = Cipher(algorithms.AES(k_enc_recovered), modes.CBC(iv))
        dec = cipher_dec.decryptor()
        padded_dec = dec.update(ciphertext) + dec.finalize()
        unpadder = sympadding.PKCS7(128).unpadder()
        message_server = unpadder.update(padded_dec) + unpadder.finalize()
        
        self.assertEqual(message, message_server)
        
        # CLIENTE DESTINO: Decifrar (sem backdoor)
        cipher_client = Cipher(algorithms.AES(k_enc), modes.CBC(iv))
        dec_client = cipher_client.decryptor()
        padded_client = dec_client.update(ciphertext) + dec_client.finalize()
        unpadder_client = sympadding.PKCS7(128).unpadder()
        message_client = unpadder_client.update(padded_client) + unpadder_client.finalize()
        
        self.assertEqual(message, message_client)

    def test_signed_message_verification(self):
        """
        Testa mensagem cifrada + assinatura digital.
        
        Input: mensagem + assinatura RSA-PSS
        Output: mensagem verificada com assinatura válida
        
        Simula comando /send_signed do sistema.
        """
        # Setup RSA
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        
        # Setup sessão
        k_enc = os.urandom(16)
        k_mac = hashlib.sha256(k_enc).digest()
        
        # Mensagem original
        msg_text = "Important signed message"
        msg_bytes = msg_text.encode("utf-8")
        
        # Assinar mensagem
        signature = private_key.sign(
            msg_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        
        # Embedar assinatura
        b64_sig = base64.b64encode(signature).decode("utf-8")
        plaintext = (msg_text + "||SIG||" + b64_sig).encode("utf-8")
        
        # Cifrar (simplificado)
        iv = os.urandom(16)
        padder = sympadding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(k_enc), modes.CBC(iv))
        enc = cipher.encryptor()
        ciphertext = enc.update(padded) + enc.finalize()
        
        # Decifrar
        dec = cipher.decryptor()
        padded_back = dec.update(ciphertext) + dec.finalize()
        unpadder = sympadding.PKCS7(128).unpadder()
        plaintext_back = unpadder.update(padded_back) + unpadder.finalize()
        
        text = plaintext_back.decode("utf-8")
        
        # Extrair e verificar assinatura
        self.assertIn("||SIG||", text)
        msg_part, sig_b64 = text.rsplit("||SIG||", 1)
        sig_bytes = base64.b64decode(sig_b64.encode("utf-8"))
        
        # Verificar assinatura
        try:
            public_key.verify(
                sig_bytes,
                msg_part.encode("utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            verified = True
        except Exception:
            verified = False
        
        self.assertTrue(verified)
        self.assertEqual(msg_part, msg_text)


class TestBase64Encoding(unittest.TestCase):
    """
    Testes para a codificação de Base64 que é usada no protocolo.
    
    Valida: encoding/decoding de bytes criptográficos
    """

    def test_base64_roundtrip(self):
        """
        Testa encode/decode Base64.
        
        Input: bytes aleatórios
        Output: bytes originais após encode/decode
        """
        data = os.urandom(100)
        encoded = base64.b64encode(data).decode("utf-8")
        decoded = base64.b64decode(encoded.encode("utf-8"))
        
        self.assertEqual(data, decoded)

    def test_base64_protocol_fields(self):
        """
        Testa o encoding de campos do protocolo MSG.
        
        Input: header, blob, iv, cipher, tag
        Output: strings base64 válidas
        """
        header = b"alice->bob"
        blob = os.urandom(16)
        iv = os.urandom(16)
        cipher = os.urandom(64)
        tag = os.urandom(32)
        
        b64_header = base64.b64encode(header).decode("utf-8")
        b64_blob = base64.b64encode(blob).decode("utf-8")
        b64_iv = base64.b64encode(iv).decode("utf-8")
        b64_cipher = base64.b64encode(cipher).decode("utf-8")
        b64_tag = base64.b64encode(tag).decode("utf-8")
        
        # Verificar que são strings válidas
        self.assertIsInstance(b64_header, str)
        self.assertIsInstance(b64_blob, str)
        
        # Verificar roundtrip
        self.assertEqual(header, base64.b64decode(b64_header))
        self.assertEqual(blob, base64.b64decode(b64_blob))


def run_all_tests():
    """
    Executa todos os testes e mostra os resultados.
    
    Input: None
    Output: relatório de testes no terminal
    """
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Adicionar todos os testes
    suite.addTests(loader.loadTestsFromTestCase(TestCryptographicFunctions))
    suite.addTests(loader.loadTestsFromTestCase(TestBackdoorMechanism))
    suite.addTests(loader.loadTestsFromTestCase(TestRSAOperations))
    suite.addTests(loader.loadTestsFromTestCase(TestDiffieHellmanX25519))
    suite.addTests(loader.loadTestsFromTestCase(TestProtocolIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestBase64Encoding))
    
    # Nivel de verbosidade
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Resultados
    print("\n" + "="*70)
    print("RESULTADO DOS TESTES")
    print("="*70)
    print(f"Testes executados: {result.testsRun}")
    print(f"Sucessos: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Falhas: {len(result.failures)}")
    print(f"Erros: {len(result.errors)}")
    print("="*70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)