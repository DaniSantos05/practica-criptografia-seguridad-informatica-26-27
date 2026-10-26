"""
PUNTO 1 · Registro y autenticación de usuarios.
Pruebas de banco/cripto/punto1_autenticacion.py y del registro/login del banco.
"""

import pytest

from banco.banco import ErrorBanco
from banco.cripto import punto1_autenticacion as autenticacion
from tests.conftest import PASSWORD_ANA, PASSWORD_LUIS

# ------------------------------------------------------------- casos correctos


def test_password_correcta_se_acepta():
    guardado = autenticacion.hash_password("una frase de prueba larga")
    assert autenticacion.verificar_password("una frase de prueba larga", guardado)


def test_registro_e_inicio_de_sesion(banco):
    banco.registrar("ana", PASSWORD_ANA)
    assert banco.iniciar_sesion("ana", PASSWORD_ANA) == "ana"


def test_misma_password_da_resumenes_distintos_gracias_a_la_sal():
    a = autenticacion.hash_password("password123456")
    b = autenticacion.hash_password("password123456")
    assert a["sal"] != b["sal"]
    assert a["hash"] != b["hash"]


def test_la_password_no_se_guarda(banco, tmp_path):
    banco.registrar("ana", PASSWORD_ANA)
    assert PASSWORD_ANA not in (tmp_path / "usuarios.json").read_text(encoding="utf-8")

# --------------------------------------------------------------- casos de error


def test_password_incorrecta_se_rechaza():
    guardado = autenticacion.hash_password("una frase de prueba larga")
    assert not autenticacion.verificar_password("una frase de prueba larga.", guardado)


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


def test_login_con_password_incorrecta_se_rechaza(banco):
    banco.registrar("ana", PASSWORD_ANA)
    with pytest.raises(ErrorBanco, match="incorrectos"):
        banco.iniciar_sesion("ana", "contraseña equivocada")


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
    # Aunque ahora la contraseña sea correcta, la cuenta está bloqueada
    with pytest.raises(ErrorBanco, match="bloqueada"):
        banco.iniciar_sesion("ana", PASSWORD_ANA)
