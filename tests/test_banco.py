"""Pruebas del funcionamiento del banco: casos normales y casos de error."""

import pytest

from banco.banco import Banco, ErrorBanco, FraseMaestraIncorrecta, OrdenRechazada
from tests.conftest import PASSWORD_ANA, PASSWORD_LUIS


# ------------------------------------------------------------ arranque

def test_frase_maestra_incorrecta_impide_arrancar(tmp_path):
    Banco(tmp_path, "frase maestra correcta", mostrar_registro=False)
    with pytest.raises(FraseMaestraIncorrecta):
        Banco(tmp_path, "frase maestra INCORRECTA", mostrar_registro=False)


def test_frase_maestra_correcta_recupera_los_datos(tmp_path):
    banco = Banco(tmp_path, "frase maestra correcta", mostrar_registro=False)
    banco.registrar("ana", PASSWORD_ANA)
    otra_vez = Banco(tmp_path, "frase maestra correcta", mostrar_registro=False)
    assert otra_vez.consultar_cuenta("ana")["saldo_centimos"] == 100_000


def test_los_ficheros_no_contienen_datos_en_claro(banco_con_clientes, tmp_path):
    banco_con_clientes.transferir("ana", PASSWORD_ANA, banco_con_clientes.consultar_cuenta("luis")["iban"],
                                  1234, "Concepto secreto")
    for nombre in ["usuarios.json", "cuentas.json", "movimientos.json", "justificantes.json", "config_banco.json"]:
        texto = (tmp_path / nombre).read_text(encoding="utf-8")
        assert "Concepto secreto" not in texto
        assert PASSWORD_ANA not in texto
        assert "PRIVATE KEY" not in texto


# ------------------------------------------------------- registro y login

def test_registro_e_inicio_de_sesion(banco):
    banco.registrar("ana", PASSWORD_ANA)
    assert banco.iniciar_sesion("ana", PASSWORD_ANA) == "ana"


@pytest.mark.parametrize("password, motivo", [
    ("corta", "al menos 12"),
    ("password1234", "demasiado común"),
    ("soy ana y esta es mi clave", "nombre de usuario"),
])
def test_contrasenas_debiles_se_rechazan(banco, password, motivo):
    with pytest.raises(ErrorBanco, match=motivo):
        banco.registrar("ana", password)


def test_usuario_duplicado_se_rechaza(banco):
    banco.registrar("ana", PASSWORD_ANA)
    with pytest.raises(ErrorBanco, match="ya existe"):
        banco.registrar("ana", PASSWORD_LUIS)


def test_password_incorrecta_y_usuario_inexistente_dan_el_mismo_mensaje(banco):
    banco.registrar("ana", PASSWORD_ANA)
    with pytest.raises(ErrorBanco) as error1:
        banco.iniciar_sesion("ana", "contraseña equivocada")
    with pytest.raises(ErrorBanco) as error2:
        banco.iniciar_sesion("nadie", "contraseña equivocada")
    assert str(error1.value) == str(error2.value)


def test_bloqueo_tras_cinco_intentos_fallidos(banco):
    banco.registrar("ana", PASSWORD_ANA)
    for _ in range(5):
        with pytest.raises(ErrorBanco):
            banco.iniciar_sesion("ana", "contraseña equivocada")
    with pytest.raises(ErrorBanco, match="bloqueada"):
        banco.iniciar_sesion("ana", PASSWORD_ANA)


# ----------------------------------------------------------- transferencias

def test_transferencia_correcta_mueve_el_dinero(banco_con_clientes):
    banco = banco_con_clientes
    iban_luis = banco.consultar_cuenta("luis")["iban"]
    banco.transferir("ana", PASSWORD_ANA, iban_luis, 2550, "Cena")
    assert banco.consultar_cuenta("ana")["saldo_centimos"] == 100_000 - 2550
    assert banco.consultar_cuenta("luis")["saldo_centimos"] == 100_000 + 2550


def test_transferencia_con_password_incorrecta_se_rechaza(banco_con_clientes):
    iban_luis = banco_con_clientes.consultar_cuenta("luis")["iban"]
    with pytest.raises(ErrorBanco, match="Contraseña incorrecta"):
        banco_con_clientes.transferir("ana", "no es la contraseña", iban_luis, 100, "x")


def test_saldo_insuficiente_se_rechaza(banco_con_clientes):
    iban_luis = banco_con_clientes.consultar_cuenta("luis")["iban"]
    with pytest.raises(OrdenRechazada, match="saldo insuficiente"):
        banco_con_clientes.transferir("ana", PASSWORD_ANA, iban_luis, 100_001, "x")


def test_cuenta_destino_inexistente_se_rechaza(banco_con_clientes):
    with pytest.raises(OrdenRechazada, match="no existe"):
        banco_con_clientes.transferir("ana", PASSWORD_ANA, "ES" + "0" * 22, 100, "x")


def test_transferencia_a_uno_mismo_se_rechaza(banco_con_clientes):
    iban_ana = banco_con_clientes.consultar_cuenta("ana")["iban"]
    with pytest.raises(OrdenRechazada, match="misma cuenta"):
        banco_con_clientes.transferir("ana", PASSWORD_ANA, iban_ana, 100, "x")


# ------------------------------------------------------------- justificantes

def test_justificante_valido_se_verifica(banco_con_clientes):
    iban_luis = banco_con_clientes.consultar_cuenta("luis")["iban"]
    justificante = banco_con_clientes.transferir("ana", PASSWORD_ANA, iban_luis, 500, "Libro")
    _, valido = banco_con_clientes.verificar_justificante(justificante)
    assert valido


def test_justificante_solo_lo_ven_ordenante_y_beneficiario(banco_con_clientes):
    banco = banco_con_clientes
    banco.registrar("eva", "Soy la atacante malvada 666")
    justificante = banco.transferir("ana", PASSWORD_ANA, banco.consultar_cuenta("luis")["iban"], 500, "Libro")
    id_orden = justificante["contenido"]["orden"]["id_orden"]
    assert banco.obtener_justificante("ana", id_orden) == justificante
    assert banco.obtener_justificante("luis", id_orden) == justificante
    with pytest.raises(ErrorBanco):
        banco.obtener_justificante("eva", id_orden)


def test_justificante_con_formato_invalido_no_es_valido(banco):
    _, valido = banco.verificar_justificante({"esto": "no es un justificante"})
    assert not valido
