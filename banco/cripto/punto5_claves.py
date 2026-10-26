"""
PUNTO 5 DEL ENUNCIADO: Generación y almacenamiento de claves.

  "También es posible no almacenar la clave [...] si se deriva/genera a partir
   de una contraseña del usuario."
  "La clave privada deberá mantenerse confidencial y almacenarse protegida."

Decisiones:
  - Ninguna clave simétrica se guarda: se derivan de contraseñas con Argon2id.
      * Clave maestra del banco  <- frase maestra que se escribe al arrancar.
      * Clave que protege la clave privada de cada cliente <- su contraseña.
  - De la clave maestra salen subclaves independientes con HKDF-SHA256
    (una para cifrar y otra para el HMAC).
  - Las claves privadas se guardan en formato PKCS#8 cifradas con AES-256-GCM.

Relación con la asignatura: tema 4 (claves independientes para cifrado y MAC),
tema 6 ("no se usa K directamente, sino K' = KDF(K)") y tema 8
(almacenamiento protegido de claves privadas).
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from banco.cripto.comun import LONGITUD_CLAVE
from banco.cripto.punto1_autenticacion import _argon2id
from banco.cripto.punto2_cifrado import cifrar, descifrar


def derivar_clave_de_password(password, sal):
    """
    Obtiene una clave de 256 bits a partir de una contraseña (con Argon2id).
    Así la clave no se guarda en ningún sitio: se recalcula cuando se escribe
    la contraseña. Con una contraseña incorrecta sale otra clave distinta.
    """
    return _argon2id(sal).derive(password.encode("utf-8"))


def derivar_subclave(clave_maestra, proposito):
    """
    A partir de la clave maestra obtiene una subclave independiente de 256 bits
    para cada uso. El parámetro 'info' (el propósito) hace que cada subclave
    sea distinta. Usar claves distintas para cifrado y MAC es la forma sólida
    de hacerlo (tema 4).
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=LONGITUD_CLAVE,
        salt=None,
        info=("BancoSeguro: " + proposito).encode("utf-8"),
    )
    return hkdf.derive(clave_maestra)


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
