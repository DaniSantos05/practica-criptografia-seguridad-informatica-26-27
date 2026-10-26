"""Preparación común de los tests: un banco nuevo en una carpeta temporal."""

import pytest

from banco.banco import Banco

PASSWORD_ANA = "Mi perro se llama Toby 2026"
PASSWORD_LUIS = "La playa en verano 1999"


@pytest.fixture
def banco(tmp_path):
    """Banco vacío en una carpeta temporal (no toca los datos reales)."""
    return Banco(tmp_path, "frase maestra de los tests", mostrar_registro=False)


@pytest.fixture
def banco_con_clientes(banco):
    """Banco con dos clientes: ana y luis (1.000 € cada uno)."""
    banco.registrar("ana", PASSWORD_ANA)
    banco.registrar("luis", PASSWORD_LUIS)
    return banco


def iban_de(banco, usuario):
    return banco.consultar_cuenta(usuario)["iban"]
