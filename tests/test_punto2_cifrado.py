"""
PUNTO 2 · Cifrado autenticado (AES-256-GCM).
Pruebas de banco/cripto/punto2_cifrado.py y del cifrado de los datos del banco.
"""

import os

import pytest

from banco.banco import ErrorIntegridad
from banco.cripto import punto2_cifrado as cifrado
from banco.cripto.comun import ErrorCriptografico
from tests.conftest import PASSWORD_ANA, iban_de


def cambiar_un_byte(texto_hex, posicion=0):
    datos = bytearray.fromhex(texto_hex)
    datos[posicion] ^= 1
    return datos.hex()

# ------------------------------------------------------------- casos correctos


def test_cifrar_y_descifrar():
    clave = os.urandom(32)
    paquete = cifrado.cifrar(clave, b"saldo: 1000", b"cuenta:ES01")
    assert cifrado.descifrar(clave, paquete, b"cuenta:ES01") == b"saldo: 1000"


def test_el_nonce_nunca_se_repite():
    clave = os.urandom(32)
    nonces = {cifrado.cifrar(clave, b"mismo mensaje", b"")["nonce"] for _ in range(1000)}
    assert len(nonces) == 1000


def test_mismo_mensaje_da_cifrados_distintos():
    clave = os.urandom(32)
    assert cifrado.cifrar(clave, b"hola", b"")["cifrado"] != cifrado.cifrar(clave, b"hola", b"")["cifrado"]


def test_los_ficheros_del_banco_no_contienen_datos_en_claro(banco_con_clientes, tmp_path):
    banco_con_clientes.transferir("ana", PASSWORD_ANA, iban_de(banco_con_clientes, "luis"), 1234, "Concepto secreto")
    for nombre in ["usuarios.json", "cuentas.json", "movimientos.json", "justificantes.json"]:
        texto = (tmp_path / nombre).read_text(encoding="utf-8")
        assert "Concepto secreto" not in texto
        assert "saldo_centimos" not in texto

# --------------------------------------------------------------- casos de error


def test_cifrado_modificado_se_rechaza():
    clave = os.urandom(32)
    paquete = cifrado.cifrar(clave, b"saldo: 1000", b"")
    paquete["cifrado"] = cambiar_un_byte(paquete["cifrado"], 0)
    with pytest.raises(ErrorCriptografico):
        cifrado.descifrar(clave, paquete, b"")


def test_tag_modificado_se_rechaza():
    clave = os.urandom(32)
    paquete = cifrado.cifrar(clave, b"saldo: 1000", b"")
    paquete["cifrado"] = cambiar_un_byte(paquete["cifrado"], -1)  # el tag de 16 bytes va al final
    with pytest.raises(ErrorCriptografico):
        cifrado.descifrar(clave, paquete, b"")


def test_nonce_modificado_se_rechaza():
    clave = os.urandom(32)
    paquete = cifrado.cifrar(clave, b"saldo: 1000", b"")
    paquete["nonce"] = cambiar_un_byte(paquete["nonce"])
    with pytest.raises(ErrorCriptografico):
        cifrado.descifrar(clave, paquete, b"")


def test_aad_distinto_se_rechaza():
    clave = os.urandom(32)
    paquete = cifrado.cifrar(clave, b"saldo: 1000", b"cuenta:ES01")
    with pytest.raises(ErrorCriptografico):
        cifrado.descifrar(clave, paquete, b"cuenta:ES02")


def test_clave_incorrecta_se_rechaza():
    paquete = cifrado.cifrar(os.urandom(32), b"saldo: 1000", b"")
    with pytest.raises(ErrorCriptografico):
        cifrado.descifrar(os.urandom(32), paquete, b"")


def test_saldo_cifrado_manipulado_en_el_disco_se_detecta(banco_con_clientes):
    cuentas = banco_con_clientes.almacen.leer("cuentas.json", {})
    estado = cuentas[iban_de(banco_con_clientes, "ana")]["estado_cifrado"]
    estado["cifrado"] = cambiar_un_byte(estado["cifrado"])
    banco_con_clientes.almacen.guardar("cuentas.json", cuentas)
    with pytest.raises(ErrorIntegridad, match="manipulado"):
        banco_con_clientes.consultar_cuenta("ana")
