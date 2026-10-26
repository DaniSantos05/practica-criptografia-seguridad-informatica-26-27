"""
PUNTO 4 · Firma digital (ECDSA P-256 + SHA-256).
Pruebas de banco/cripto/punto4_firma.py, de las transferencias firmadas y de
los justificantes.
"""

import pytest

from banco.banco import ErrorBanco, OrdenRechazada
from banco.cripto import comun
from banco.cripto import punto4_firma as firmas
from tests.conftest import PASSWORD_ANA, iban_de


def orden_firmada(banco, importe=500):
    orden = banco.preparar_orden("ana", iban_de(banco, "luis"), importe, "Libro")
    return orden, banco.firmar_orden("ana", PASSWORD_ANA, orden), banco.certificado_de("ana")

# ------------------------------------------------------------- casos correctos


def test_firma_valida_se_acepta():
    clave = firmas.generar_par_claves()
    assert firmas.verificar_firma(clave.public_key(), b"orden", firmas.firmar(clave, b"orden"))


def test_json_canonico_no_depende_del_orden_de_las_claves():
    assert comun.json_canonico({"a": 1, "b": 2}) == comun.json_canonico({"b": 2, "a": 1})


def test_transferencia_firmada_mueve_el_dinero(banco_con_clientes):
    banco = banco_con_clientes
    banco.transferir("ana", PASSWORD_ANA, iban_de(banco, "luis"), 2550, "Cena")
    assert banco.consultar_cuenta("ana")["saldo_centimos"] == 100_000 - 2550
    assert banco.consultar_cuenta("luis")["saldo_centimos"] == 100_000 + 2550


def test_justificante_valido_se_verifica(banco_con_clientes):
    orden, firma, certificado = orden_firmada(banco_con_clientes)
    justificante = banco_con_clientes.ejecutar_orden(orden, firma, certificado)
    comprobaciones, valido = banco_con_clientes.verificar_justificante(justificante)
    assert valido and len(comprobaciones) == 4

# --------------------------------------------------------------- casos de error


def test_firma_de_mensaje_modificado_se_rechaza():
    clave = firmas.generar_par_claves()
    firma = firmas.firmar(clave, b"Transfer 100 euros")
    assert not firmas.verificar_firma(clave.public_key(), b"Transfer 900 euros", firma)


def test_firma_alterada_se_rechaza():
    clave = firmas.generar_par_claves()
    firma = bytearray.fromhex(firmas.firmar(clave, b"orden"))
    firma[10] ^= 1
    assert not firmas.verificar_firma(clave.public_key(), b"orden", firma.hex())


def test_firma_con_otra_clave_se_rechaza():
    firma = firmas.firmar(firmas.generar_par_claves(), b"orden")
    assert not firmas.verificar_firma(firmas.generar_par_claves().public_key(), b"orden", firma)


def test_orden_con_importe_modificado_se_rechaza(banco_con_clientes):
    orden, firma, certificado = orden_firmada(banco_con_clientes)
    orden["importe_centimos"] = 90_000
    with pytest.raises(OrdenRechazada, match="firma ECDSA no es válida"):
        banco_con_clientes.ejecutar_orden(orden, firma, certificado)
    assert banco_con_clientes.consultar_cuenta("ana")["saldo_centimos"] == 100_000  # no se movió nada


def test_justificante_alterado_no_es_valido(banco_con_clientes):
    orden, firma, certificado = orden_firmada(banco_con_clientes)
    justificante = banco_con_clientes.ejecutar_orden(orden, firma, certificado)
    justificante["contenido"]["orden"]["importe_centimos"] = 500_000
    _, valido = banco_con_clientes.verificar_justificante(justificante)
    assert not valido


def test_justificante_con_formato_invalido_no_es_valido(banco):
    _, valido = banco.verificar_justificante({"esto": "no es un justificante"})
    assert not valido


def test_justificante_solo_lo_ven_ordenante_y_beneficiario(banco_con_clientes):
    banco = banco_con_clientes
    banco.registrar("eva", "Soy la atacante malvada 666")
    justificante = banco.transferir("ana", PASSWORD_ANA, iban_de(banco, "luis"), 500, "Libro")
    id_orden = justificante["contenido"]["orden"]["id_orden"]
    assert banco.obtener_justificante("ana", id_orden) == justificante
    assert banco.obtener_justificante("luis", id_orden) == justificante
    with pytest.raises(ErrorBanco):
        banco.obtener_justificante("eva", id_orden)


@pytest.mark.parametrize("destino, importe, motivo", [
    ("luis", 100_001, "saldo insuficiente"),
    ("ana", 100, "misma cuenta"),
    ("ES" + "0" * 22, 100, "no existe"),
])
def test_ordenes_no_validas_se_rechazan(banco_con_clientes, destino, importe, motivo):
    iban = destino if destino.startswith("ES") else iban_de(banco_con_clientes, destino)
    with pytest.raises(OrdenRechazada, match=motivo):
        banco_con_clientes.transferir("ana", PASSWORD_ANA, iban, importe, "x")
