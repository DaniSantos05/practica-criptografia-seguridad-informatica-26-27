"""
PUNTO 5 DEL ENUNCIADO (y apoyo al 4): vincular la clave pública con su dueño.

  "La clave pública podrá distribuirse, pero cuando sea necesario vincularla de
   forma fiable con una identidad deberá utilizarse un mecanismo de
   autenticación adecuado, por ejemplo certificados y una PKI."

Decisión: el banco tiene su propia autoridad de certificación (CA). Al
registrarse, cada cliente recibe un certificado X.509 que dice "esta clave
pública es de este cliente", firmado por la CA. Al verificar una firma, el
banco comprueba también el certificado.

Relación con la asignatura: tema 8 (certificados X.509, PKI, keyUsage,
verificación) y práctica 4 (una firma válida no basta: hay que comprobar
identidad, fechas y usos; caso attacker.com).
"""

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from banco.cripto.comun import ErrorCriptografico


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
    para certificados cualificados (tema 10).
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
