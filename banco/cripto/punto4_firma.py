"""
PUNTO 4 DEL ENUNCIADO: Generación/verificación de firma digital.

  "Se utilizarán algoritmos y parámetros actuales (por ejemplo, ECDSA con curvas
   seguras). La aplicación deberá comprobar correctamente el resultado de la
   verificación y rechazar firmas modificadas o inválidas."

Decisión: ECDSA con la curva P-256 y SHA-256.
  - Los clientes firman cada orden de transferencia (autenticidad, integridad
    y no repudio).
  - El banco firma cada justificante.

Relación con la asignatura: tema 7 (firma digital, "resume y firma", esquema
aleatorio con apéndice), tema 6 (P-256 ≈ 128 bits de seguridad ≈ RSA-3072) y
práctica 3 (verificar exactamente el mismo mensaje y hash; replay).
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

CURVA = ec.SECP256R1()  # P-256: clave privada de 256 bits


def generar_par_claves():
    """Genera un par de claves de firma ECDSA sobre la curva P-256."""
    return ec.generate_private_key(CURVA)


def firmar(clave_privada, datos):
    """
    Firma 'datos'. Sigue el paradigma "resume y firma" (tema 7): primero se
    calcula SHA-256 de los datos y después se firma ese resumen.
    ECDSA es un esquema aleatorio: cada firma usa un número secreto nuevo que
    genera la librería de forma segura (repetirlo revelaría la clave privada).
    """
    return clave_privada.sign(datos, ec.ECDSA(hashes.SHA256())).hex()


def verificar_firma(clave_publica, datos, firma_hex):
    """Devuelve True solo si la firma corresponde exactamente a esos datos."""
    try:
        clave_publica.verify(bytes.fromhex(firma_hex), datos, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
