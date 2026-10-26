"""
OTRAS CONSIDERACIONES · Reutilización o repetición de mensajes (replay).
"""

from datetime import timedelta

import pytest

from banco.banco import OrdenRechazada, ahora
from tests.conftest import PASSWORD_ANA, iban_de


def test_una_orden_solo_se_ejecuta_una_vez(banco_con_clientes):
    banco = banco_con_clientes
    orden = banco.preparar_orden("ana", iban_de(banco, "luis"), 5000, "Cena")
    firma = banco.firmar_orden("ana", PASSWORD_ANA, orden)
    banco.ejecutar_orden(orden, firma, banco.certificado_de("ana"))
    with pytest.raises(OrdenRechazada, match="ya se ejecutó"):
        banco.ejecutar_orden(orden, firma, banco.certificado_de("ana"))
    assert banco.consultar_cuenta("ana")["saldo_centimos"] == 100_000 - 5000  # se cobró una sola vez


def test_cada_orden_tiene_un_identificador_distinto(banco_con_clientes):
    iban_luis = iban_de(banco_con_clientes, "luis")
    ids = {banco_con_clientes.preparar_orden("ana", iban_luis, 1, "x")["id_orden"] for _ in range(100)}
    assert len(ids) == 100


def test_orden_antigua_se_rechaza_aunque_este_bien_firmada(banco_con_clientes):
    banco = banco_con_clientes
    orden = banco.preparar_orden("ana", iban_de(banco, "luis"), 5000, "Antigua")
    orden["fecha"] = (ahora() - timedelta(hours=1)).isoformat()
    firma = banco.firmar_orden("ana", PASSWORD_ANA, orden)
    with pytest.raises(OrdenRechazada, match="caducado"):
        banco.ejecutar_orden(orden, firma, banco.certificado_de("ana"))
