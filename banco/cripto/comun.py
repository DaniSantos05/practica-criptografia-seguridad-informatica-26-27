"""Utilidades que usan varios puntos: errores, aleatoriedad y serialización."""

import hmac
import json
import os

LONGITUD_SAL = 16    # bytes (128 bits)
LONGITUD_CLAVE = 32  # bytes (256 bits) -> AES-256 y HMAC-SHA256


class ErrorCriptografico(Exception):
    """Una comprobación criptográfica ha fallado (tag, firma, certificado...)."""


def generar_sal():
    """
    Sal aleatoria con el generador criptográficamente seguro del sistema
    (os.urandom). Nunca se usa el módulo 'random', que es predecible.
    """
    return os.urandom(LONGITUD_SAL)


def json_canonico(datos):
    """
    Convierte un diccionario en bytes SIEMPRE de la misma forma (claves ordenadas,
    sin espacios). Es necesario para firmar o calcular un HMAC: si el mismo
    contenido se serializase de dos formas distintas, la verificación fallaría.
    """
    return json.dumps(datos, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def iguales(a, b):
    """Compara dos cadenas en tiempo constante (no da pistas por el tiempo que tarda)."""
    return hmac.compare_digest(a, b)
