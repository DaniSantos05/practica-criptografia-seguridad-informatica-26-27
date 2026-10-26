"""CALIDAD DEL SOFTWARE · Pruebas de la interfaz web (sesión, CSRF, validación de entradas)."""

import re

import pytest

from app import crear_app, importe_a_centimos
from banco.banco import ErrorBanco
from tests.conftest import PASSWORD_ANA


@pytest.fixture
def cliente(banco_con_clientes):
    app = crear_app(banco_con_clientes)
    app.config.update(TESTING=True)
    return app.test_client()


def token(cliente, ruta):
    """Lee el token CSRF del formulario de una página."""
    html = cliente.get(ruta).get_data(as_text=True)
    return re.search(r'name="csrf" value="([0-9a-f]+)"', html).group(1)


def entrar(cliente, usuario="ana", password=PASSWORD_ANA):
    return cliente.post("/login", data={"csrf": token(cliente, "/login"), "usuario": usuario, "password": password},
                        follow_redirects=True)


def test_login_correcto_muestra_la_cuenta(cliente):
    respuesta = entrar(cliente)
    assert "Saldo disponible" in respuesta.get_data(as_text=True)


def test_login_incorrecto_muestra_error_generico(cliente):
    respuesta = entrar(cliente, password="contraseña equivocada")
    assert "Usuario o contraseña incorrectos" in respuesta.get_data(as_text=True)


def test_la_cuenta_requiere_iniciar_sesion(cliente):
    respuesta = cliente.get("/cuenta")
    assert respuesta.status_code == 302 and "/login" in respuesta.headers["Location"]


def test_formulario_sin_token_csrf_se_rechaza(cliente):
    respuesta = cliente.post("/login", data={"usuario": "ana", "password": PASSWORD_ANA})
    assert respuesta.status_code == 400


def test_transferencia_desde_la_web(cliente, banco_con_clientes):
    entrar(cliente)
    iban_luis = banco_con_clientes.consultar_cuenta("luis")["iban"]
    respuesta = cliente.post("/transferir", data={
        "csrf": token(cliente, "/transferir"), "iban_destino": iban_luis, "importe": "12,50",
        "concepto": "Prueba", "password": PASSWORD_ANA}, follow_redirects=True)
    assert "realizada y firmada correctamente" in respuesta.get_data(as_text=True)
    assert banco_con_clientes.consultar_cuenta("luis")["saldo_centimos"] == 100_000 + 1250


def test_datos_manipulados_no_se_muestran(cliente, banco_con_clientes):
    entrar(cliente)
    cuentas = banco_con_clientes.almacen.leer("cuentas.json", {})
    iban_ana = banco_con_clientes.consultar_cuenta("ana")["iban"]
    cuentas[iban_ana]["estado_cifrado"]["cifrado"] = "00" + cuentas[iban_ana]["estado_cifrado"]["cifrado"][2:]
    banco_con_clientes.almacen.guardar("cuentas.json", cuentas)
    respuesta = cliente.get("/cuenta")
    assert respuesta.status_code == 409
    assert "datos manipulados" in respuesta.get_data(as_text=True)


@pytest.mark.parametrize("texto, centimos", [("50", 5000), ("50,5", 5050), ("1.250,75", 125075), ("0.01", 1)])
def test_importes_validos(texto, centimos):
    assert importe_a_centimos(texto) == centimos


@pytest.mark.parametrize("texto", ["0", "-5", "abc", "1,234", "NaN", "Infinity", ""])
def test_importes_no_validos(texto):
    with pytest.raises(ErrorBanco):
        importe_a_centimos(texto)
