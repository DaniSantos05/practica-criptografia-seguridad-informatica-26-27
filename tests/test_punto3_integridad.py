"""
PUNTO 3 · Etiquetas de autenticación de mensajes (HMAC-SHA256).
Pruebas de banco/cripto/punto3_integridad.py y del libro de movimientos encadenado.
"""

import os

import pytest

from banco.banco import ErrorIntegridad
from banco.cripto import punto3_integridad as integridad
from tests.conftest import PASSWORD_ANA, iban_de


@pytest.fixture
def banco_con_movimientos(banco_con_clientes):
    """Ana ha hecho dos transferencias a Luis: tiene 3 movimientos."""
    for importe in (1000, 2000):
        banco_con_clientes.transferir("ana", PASSWORD_ANA, iban_de(banco_con_clientes, "luis"), importe, "Pago")
    return banco_con_clientes


def manipular_movimientos(banco, usuario, cambio):
    movimientos = banco.almacen.leer("movimientos.json", {})
    cambio(movimientos, iban_de(banco, usuario))
    banco.almacen.guardar("movimientos.json", movimientos)

# ------------------------------------------------------------- casos correctos


def test_hmac_correcto_se_acepta():
    clave = os.urandom(32)
    assert integridad.verificar_hmac(clave, b"movimiento", integridad.calcular_hmac(clave, b"movimiento"))


def test_libro_de_movimientos_integro_se_verifica(banco_con_movimientos):
    assert len(banco_con_movimientos.consultar_cuenta("ana")["movimientos"]) == 3

# --------------------------------------------------------------- casos de error


def test_hmac_con_datos_modificados_se_rechaza():
    clave = os.urandom(32)
    mac = integridad.calcular_hmac(clave, b"importe=50")
    assert not integridad.verificar_hmac(clave, b"importe=5000", mac)


def test_hmac_con_otra_clave_se_rechaza():
    mac = integridad.calcular_hmac(os.urandom(32), b"movimiento")
    assert not integridad.verificar_hmac(os.urandom(32), b"movimiento", mac)


def test_hmac_modificado_se_rechaza(banco_con_movimientos):
    def cambio(movimientos, iban):
        movimientos[iban][1]["hmac"] = "0" * 64
    manipular_movimientos(banco_con_movimientos, "ana", cambio)
    with pytest.raises(ErrorIntegridad, match="HMAC no coincide"):
        banco_con_movimientos.consultar_cuenta("ana")


def test_reordenar_movimientos_se_detecta(banco_con_movimientos):
    def cambio(movimientos, iban):
        movimientos[iban][1], movimientos[iban][2] = movimientos[iban][2], movimientos[iban][1]
    manipular_movimientos(banco_con_movimientos, "ana", cambio)
    with pytest.raises(ErrorIntegridad, match="reordenado"):
        banco_con_movimientos.consultar_cuenta("ana")


def test_borrar_un_movimiento_intermedio_se_detecta(banco_con_movimientos):
    manipular_movimientos(banco_con_movimientos, "ana", lambda movimientos, iban: movimientos[iban].pop(1))
    with pytest.raises(ErrorIntegridad):
        banco_con_movimientos.consultar_cuenta("ana")


def test_borrar_el_ultimo_movimiento_se_detecta(banco_con_movimientos):
    manipular_movimientos(banco_con_movimientos, "ana", lambda movimientos, iban: movimientos[iban].pop())
    with pytest.raises(ErrorIntegridad, match="Faltan o sobran"):
        banco_con_movimientos.consultar_cuenta("ana")
