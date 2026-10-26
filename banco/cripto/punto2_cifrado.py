"""
PUNTO 2 DEL ENUNCIADO: Cifrado y descifrado simétrico (con cifrado autenticado).

  "Siempre que sea posible y tenga sentido su uso, se utilizará cifrado
   autenticado. [...] evitar claves, IVs o nonces constantes."

Decisión: AES-256-GCM, un modo de cifrado autenticado (AEAD). En una sola
operación da confidencialidad (nadie lee los datos) e integridad (nadie los
modifica sin que se detecte).

Relación con la asignatura: tema 3 (AES, modos de operación; por qué NO ECB ni
CBC), tema 4 (cifrado autenticado, GCM) y práctica 2 (clase AESGCM, nonce de 12
bytes con os.urandom, AAD).
"""

import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from banco.cripto.comun import ErrorCriptografico, json_canonico

LONGITUD_NONCE = 12  # bytes (96 bits): el tamaño recomendado para GCM


def cifrar(clave, datos, aad):
    """
    Cifra 'datos' con AES-256-GCM (la clave es de 256 bits).

    - El nonce es aleatorio y NUEVO en cada llamada. Repetir nonce con la misma
      clave rompería GCM: es un modo contador, como un cifrado en flujo, y
      C1 XOR C2 = M1 XOR M2 (tema 2).
    - 'aad' (datos asociados) no se cifra pero sí se autentica: ata el texto
      cifrado a su contexto (p. ej. a un IBAN concreto).
    - El resultado incluye al final el tag de autenticación de 128 bits.
    """
    nonce = os.urandom(LONGITUD_NONCE)
    cifrado = AESGCM(clave).encrypt(nonce, datos, aad)
    return {"nonce": nonce.hex(), "cifrado": cifrado.hex()}


def descifrar(clave, paquete, aad):
    """
    Descifra y COMPRUEBA la integridad. Si alguien ha cambiado un solo bit del
    texto cifrado, del tag, del nonce o del aad, el tag no coincide y se lanza
    un error: los datos manipulados nunca llegan a usarse.
    """
    try:
        return AESGCM(clave).decrypt(bytes.fromhex(paquete["nonce"]), bytes.fromhex(paquete["cifrado"]), aad)
    except (InvalidTag, ValueError, KeyError, TypeError) as error:
        raise ErrorCriptografico("El tag de AES-GCM no es válido: datos manipulados o clave incorrecta") from error


def cifrar_json(clave, datos, aad):
    """Cifra un diccionario."""
    return cifrar(clave, json_canonico(datos), aad)


def descifrar_json(clave, paquete, aad):
    """Descifra (y verifica) un diccionario."""
    return json.loads(descifrar(clave, paquete, aad).decode("utf-8"))
