"""
Operaciones criptográficas de BancoSeguro.

TODA la criptografía de la aplicación está en este fichero. El resto del código
(banco.py, app.py...) solo llama a estas funciones, así que para entender qué
algoritmos se usan basta con leer este archivo.

Resumen de decisiones (justificadas en DISENO.md):
  - Contraseñas ............ Argon2id con sal aleatoria de 16 bytes.
  - Cifrado de datos ....... AES-256-GCM (cifrado autenticado) con nonce de 96 bits.
  - Derivar subclaves ...... HKDF-SHA256 (una clave distinta para cada uso).
  - Integridad del libro ... HMAC-SHA256.
  - Firma digital .......... ECDSA con la curva P-256 y SHA-256.
  - Certificados ........... X.509 emitidos por la autoridad de certificación del banco.

Única librería criptográfica: "cryptography" (la misma de las prácticas de clase).
"""

import hmac as hmac_python  # solo para comparar valores sin fugas de tiempo
import json
import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import InvalidKey, InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID

# ---------------------------------------------------------------------------
# Parámetros
# ---------------------------------------------------------------------------

# Argon2id: función lenta y que consume memoria a propósito, para que probar
# millones de contraseñas (fuerza bruta o diccionario) sea muy caro.
ARGON2_ITERACIONES = 3
ARGON2_MEMORIA_KIB = 64 * 1024  # 64 MiB por cada cálculo
ARGON2_HILOS = 4

LONGITUD_SAL = 16  # bytes (128 bits)
LONGITUD_CLAVE = 32  # bytes (256 bits) -> AES-256 y HMAC-SHA256
LONGITUD_NONCE = 12  # bytes (96 bits), el tamaño recomendado para GCM

# Curva elíptica P-256: ~128 bits de seguridad, equivalente a RSA-3072 (tema 6).
CURVA = ec.SECP256R1()


class ErrorCriptografico(Exception):
    """Una comprobación criptográfica ha fallado (tag, firma, certificado...)."""


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

def generar_sal():
    """Sal aleatoria con el generador criptográficamente seguro del sistema."""
    return os.urandom(LONGITUD_SAL)


def json_canonico(datos):
    """
    Convierte un diccionario en bytes SIEMPRE de la misma forma (claves ordenadas,
    sin espacios). Es necesario para firmar o calcular un HMAC: si el mismo
    contenido se serializase de dos formas distintas, la verificación fallaría.
    """
    return json.dumps(datos, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------------------
# 1. Contraseñas (Argon2id)
# ---------------------------------------------------------------------------

def _argon2id(sal):
    """Crea un objeto Argon2id con nuestros parámetros. Cada objeto solo sirve una vez."""
    return Argon2id(
        salt=sal,
        length=LONGITUD_CLAVE,
        iterations=ARGON2_ITERACIONES,
        lanes=ARGON2_HILOS,
        memory_cost=ARGON2_MEMORIA_KIB,
    )


def hash_password(password):
    """
    Calcula el resumen de una contraseña para guardarlo. Nunca se guarda la
    contraseña. La sal hace que dos usuarios con la misma contraseña tengan
    resúmenes distintos e impide usar tablas precalculadas.
    """
    sal = generar_sal()
    resumen = _argon2id(sal).derive(password.encode("utf-8"))
    return {"sal": sal.hex(), "hash": resumen.hex()}


def verificar_password(password, guardado):
    """Devuelve True si la contraseña coincide con el resumen guardado."""
    sal = bytes.fromhex(guardado["sal"])
    try:
        # verify() compara en tiempo constante (no da pistas por el tiempo de respuesta)
        _argon2id(sal).verify(password.encode("utf-8"), bytes.fromhex(guardado["hash"]))
        return True
    except InvalidKey:
        return False


def derivar_clave_de_password(password, sal):
    """
    Obtiene una clave AES de 256 bits a partir de una contraseña (con Argon2id).
    Se usa para proteger claves privadas: así la clave de cifrado no se guarda
    en ningún sitio, se recalcula cuando el usuario escribe su contraseña.
    """
    return _argon2id(sal).derive(password.encode("utf-8"))


# ---------------------------------------------------------------------------
# 2. Derivación de subclaves (HKDF)
# ---------------------------------------------------------------------------

def derivar_subclave(clave_maestra, proposito):
    """
    A partir de una clave maestra obtiene una subclave independiente para cada
    uso (una para cifrar, otra para el HMAC...). Usar claves distintas para
    cifrado y MAC es la forma sólida de hacerlo (tema 4).
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=LONGITUD_CLAVE,
        salt=None,
        info=("BancoSeguro: " + proposito).encode("utf-8"),
    )
    return hkdf.derive(clave_maestra)


# ---------------------------------------------------------------------------
# 3. Cifrado autenticado (AES-256-GCM)
# ---------------------------------------------------------------------------

def cifrar(clave, datos, aad):
    """
    Cifra 'datos' con AES-256-GCM.

    - El nonce es aleatorio y NUEVO en cada llamada: repetir nonce con la misma
      clave rompería la seguridad de GCM (es un modo contador, tema 2 y 4).
    - 'aad' (datos asociados) no se cifra pero sí se autentica: sirve para atar
      el texto cifrado a su contexto (p. ej. a un IBAN concreto).
    - El resultado incluye el tag de autenticación de 128 bits al final.
    """
    nonce = os.urandom(LONGITUD_NONCE)
    cifrado = AESGCM(clave).encrypt(nonce, datos, aad)
    return {"nonce": nonce.hex(), "cifrado": cifrado.hex()}


def descifrar(clave, paquete, aad):
    """
    Descifra y COMPRUEBA la integridad. Si alguien ha cambiado un solo bit del
    texto cifrado, del nonce o del aad, el tag no coincide y se lanza un error:
    los datos manipulados nunca llegan a usarse.
    """
    try:
        return AESGCM(clave).decrypt(bytes.fromhex(paquete["nonce"]), bytes.fromhex(paquete["cifrado"]), aad)
    except (InvalidTag, ValueError, KeyError, TypeError) as error:
        raise ErrorCriptografico("El tag de AES-GCM no es válido: datos manipulados o clave incorrecta") from error


def cifrar_json(clave, datos, aad):
    return cifrar(clave, json_canonico(datos), aad)


def descifrar_json(clave, paquete, aad):
    return json.loads(descifrar(clave, paquete, aad).decode("utf-8"))


# ---------------------------------------------------------------------------
# 4. Códigos de autenticación de mensajes (HMAC-SHA256)
# ---------------------------------------------------------------------------

def calcular_hmac(clave, datos):
    """HMAC-SHA256 de 'datos'. Solo quien tiene la clave puede calcularlo."""
    h = hmac.HMAC(clave, hashes.SHA256())
    h.update(datos)
    return h.finalize().hex()


def verificar_hmac(clave, datos, mac_hex):
    """Comprueba un HMAC (en tiempo constante). Devuelve True o False."""
    h = hmac.HMAC(clave, hashes.SHA256())
    h.update(datos)
    try:
        h.verify(bytes.fromhex(mac_hex))
        return True
    except (InvalidSignature, ValueError):
        return False


def iguales(a, b):
    """Compara dos cadenas en tiempo constante."""
    return hmac_python.compare_digest(a, b)


# ---------------------------------------------------------------------------
# 5. Firma digital (ECDSA P-256 + SHA-256)
# ---------------------------------------------------------------------------

def generar_par_claves():
    """Genera un par de claves de firma ECDSA sobre la curva P-256."""
    return ec.generate_private_key(CURVA)


def firmar(clave_privada, datos):
    """
    Firma 'datos'. Sigue el paradigma "resume y firma" (tema 7): primero se
    calcula SHA-256 de los datos y después se firma ese resumen.
    ECDSA es un esquema aleatorio: cada firma usa un número secreto nuevo que
    genera la librería de forma segura.
    """
    return clave_privada.sign(datos, ec.ECDSA(hashes.SHA256())).hex()


def verificar_firma(clave_publica, datos, firma_hex):
    """Devuelve True solo si la firma corresponde exactamente a esos datos."""
    try:
        clave_publica.verify(bytes.fromhex(firma_hex), datos, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# 6. Almacenamiento protegido de claves privadas
# ---------------------------------------------------------------------------

def proteger_clave_privada(clave_privada, clave_cifrado, aad):
    """
    Serializa la clave privada (formato estándar PKCS#8) y la cifra con
    AES-256-GCM. La clave privada nunca se guarda en claro en el disco.
    """
    der = clave_privada.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cifrar(clave_cifrado, der, aad)


def recuperar_clave_privada(paquete, clave_cifrado, aad):
    """Descifra una clave privada. Con una clave incorrecta lanza ErrorCriptografico."""
    der = descifrar(clave_cifrado, paquete, aad)
    return serialization.load_der_private_key(der, password=None)


# ---------------------------------------------------------------------------
# 7. Certificados X.509 (PKI del banco)
# ---------------------------------------------------------------------------

def _nombre(nombre_comun):
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BancoSeguro (practica academica)"),
        x509.NameAttribute(NameOID.COMMON_NAME, nombre_comun),
    ])


def _uso_de_clave(es_ca):
    """
    keyUsage: para qué se puede usar la clave del certificado.
    - La CA solo firma certificados (key_cert_sign) y listas de revocación (crl_sign).
    - Los clientes y el banco firman documentos (digital_signature) con no
      repudio (content_commitment).
    """
    return x509.KeyUsage(
        digital_signature=not es_ca,
        content_commitment=not es_ca,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=es_ca,
        crl_sign=es_ca,
        encipher_only=False,
        decipher_only=False,
    )


def crear_certificado_ca(clave_ca, nombre, dias=5 * 365):
    """Certificado raíz autofirmado de la autoridad de certificación del banco."""
    ahora = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(_nombre(nombre))
        .issuer_name(_nombre(nombre))  # autofirmado: emisor = sujeto
        .public_key(clave_ca.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ahora)
        .not_valid_after(ahora + timedelta(days=dias))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_uso_de_clave(es_ca=True), critical=True)
        .sign(clave_ca, hashes.SHA256())
    )


def emitir_certificado(clave_ca, certificado_ca, clave_publica, nombre, dias=365):
    """
    La CA firma un certificado que asocia 'nombre' con 'clave_publica'.
    Validez corta (1 año por defecto): la Ley 6/2020 exige menos de 5 años
    para certificados cualificados.
    """
    ahora = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(_nombre(nombre))
        .issuer_name(certificado_ca.subject)
        .public_key(clave_publica)
        .serial_number(x509.random_serial_number())
        .not_valid_before(ahora)
        .not_valid_after(ahora + timedelta(days=dias))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_uso_de_clave(es_ca=False), critical=True)
        .sign(clave_ca, hashes.SHA256())
    )


def verificar_certificado(certificado, certificado_ca, nombre_esperado):
    """
    Comprueba que un certificado es de fiar. Como vimos en la práctica 4,
    NO basta con que la firma sea válida. Se comprueba:
      1. Que lo ha firmado nuestra CA.
      2. Que está dentro de su periodo de validez.
      3. Que pertenece a quien dice ser (nombre esperado).
      4. Que no es un certificado de CA y que permite firmar documentos.
    Si algo falla lanza ErrorCriptografico explicando el motivo.
    """
    # 1. Firma de la CA (y que el emisor sea nuestra CA)
    try:
        certificado.verify_directly_issued_by(certificado_ca)
    except (ValueError, TypeError, InvalidSignature) as error:
        raise ErrorCriptografico("el certificado no está emitido por la autoridad de certificación del banco") from error

    # 2. Periodo de validez
    ahora = datetime.now(timezone.utc)
    if not certificado.not_valid_before_utc <= ahora <= certificado.not_valid_after_utc:
        raise ErrorCriptografico("el certificado está caducado o todavía no es válido")

    # 3. Identidad: el nombre del certificado debe ser el esperado
    nombres = certificado.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not nombres or nombres[0].value != nombre_esperado:
        raise ErrorCriptografico(f"el certificado no pertenece a '{nombre_esperado}'")

    # 4. Usos permitidos
    try:
        es_ca = certificado.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        uso = certificado.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as error:
        raise ErrorCriptografico("al certificado le faltan extensiones obligatorias") from error
    if es_ca or not uso.digital_signature:
        raise ErrorCriptografico("el certificado no está autorizado para firmar documentos")


def certificado_a_pem(certificado):
    return certificado.public_bytes(serialization.Encoding.PEM).decode("ascii")


def pem_a_certificado(texto_pem):
    try:
        return x509.load_pem_x509_certificate(texto_pem.encode("ascii"))
    except (ValueError, AttributeError, UnicodeEncodeError) as error:
        raise ErrorCriptografico("el certificado no tiene un formato PEM válido") from error
