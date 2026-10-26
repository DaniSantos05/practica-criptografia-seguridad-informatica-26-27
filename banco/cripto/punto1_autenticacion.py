"""
PUNTO 1 DEL ENUNCIADO: Registro y autenticación de usuarios.

  "Basado en algo que sabemos: contraseñas; se deben almacenar convenientemente
   y a ser posible que sean robustas. Esta será la opción mínima obligatoria."

Decisión: la contraseña NUNCA se guarda. Se guarda su resumen Argon2id con una
sal aleatoria de 128 bits. Además se exige una contraseña robusta.

Relación con la asignatura: tema 9 (autenticación basada en secretos, gestión
de contraseñas) y práctica 1 (SHA-256 sin sal es inseguro: ataque de diccionario).
"""

from pathlib import Path

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from banco.cripto.comun import LONGITUD_CLAVE, generar_sal

# Argon2id es lento y consume memoria A PROPÓSITO: así probar millones de
# contraseñas (fuerza bruta o diccionario) es muy caro, incluso con GPU.
ARGON2_ITERACIONES = 3          # t: pasadas sobre la memoria
ARGON2_MEMORIA_KIB = 64 * 1024  # m: 64 MiB por cada cálculo
ARGON2_HILOS = 4                # p: paralelismo

LONGITUD_MINIMA_PASSWORD = 12
LONGITUD_MAXIMA_PASSWORD = 128
CONTRASENAS_COMUNES = set(
    (Path(__file__).parent / "contrasenas_comunes.txt").read_text(encoding="utf-8").split()
)


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
    Calcula el resumen de una contraseña para guardarlo.
    La sal hace que dos usuarios con la misma contraseña tengan resúmenes
    distintos e impide usar tablas precalculadas.
    """
    sal = generar_sal()
    resumen = _argon2id(sal).derive(password.encode("utf-8"))
    return {"sal": sal.hex(), "hash": resumen.hex()}


def verificar_password(password, guardado):
    """Devuelve True si la contraseña coincide con el resumen guardado."""
    sal = bytes.fromhex(guardado["sal"])
    try:
        # verify() compara en tiempo constante
        _argon2id(sal).verify(password.encode("utf-8"), bytes.fromhex(guardado["hash"]))
        return True
    except InvalidKey:
        return False


def problema_de_password(usuario, password):
    """
    Política de contraseñas robustas (tema 9, "criterios de calidad").
    Devuelve el motivo por el que la contraseña NO es válida, o None si es válida.
    """
    if len(password) < LONGITUD_MINIMA_PASSWORD:
        return f"La contraseña debe tener al menos {LONGITUD_MINIMA_PASSWORD} caracteres"
    if len(password) > LONGITUD_MAXIMA_PASSWORD:
        return f"La contraseña es demasiado larga (máximo {LONGITUD_MAXIMA_PASSWORD} caracteres)"
    if password.lower() in CONTRASENAS_COMUNES:
        return "Esa contraseña es demasiado común (aparece en diccionarios de ataque)"
    if usuario in password.lower():
        return "La contraseña no puede contener el nombre de usuario"
    return None
