"""
PUNTO 3 DEL ENUNCIADO: Generación/verificación de etiquetas de autenticación
de mensajes.

  "La información de valor que se intercambie o almacene [...] deberá disponer
   de un mecanismo de autenticación/integridad adecuado."

Decisión: HMAC-SHA256 con una clave de 256 bits, distinta de la de cifrado.
Se usa para encadenar los movimientos de cada cuenta (un "libro" sellado):
cada movimiento lleva un HMAC que incluye el HMAC del anterior, así que
modificar, mover, reordenar o borrar un movimiento rompe la cadena.

Relación con la asignatura: tema 4 (HMAC, Encrypt-then-MAC, claves
independientes para cifrado y MAC, número de secuencia contra la repetición).
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac


def calcular_hmac(clave, datos):
    """HMAC-SHA256 de 'datos' (256 bits). Solo quien tiene la clave puede calcularlo."""
    h = hmac.HMAC(clave, hashes.SHA256())
    h.update(datos)
    return h.finalize().hex()


def verificar_hmac(clave, datos, mac_hex):
    """Comprueba un HMAC en tiempo constante. Devuelve True o False."""
    h = hmac.HMAC(clave, hashes.SHA256())
    h.update(datos)
    try:
        h.verify(bytes.fromhex(mac_hex))
        return True
    except (InvalidSignature, ValueError):
        return False
