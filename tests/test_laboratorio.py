"""
Ejecuta cada ataque del laboratorio y comprueba que el banco lo rechaza con el
motivo esperado. Son las pruebas negativas que pide el enunciado.
"""

import shutil
import tempfile

import pytest

from banco.banco import ErrorBanco
from banco.laboratorio import ATAQUES, Escenario

MOTIVO_ESPERADO = {
    "ataque_modificar_importe": "firma ECDSA no es válida",
    "ataque_firma_alterada": "firma ECDSA no es válida",
    "ataque_replay": "ya se ejecutó",
    "ataque_orden_caducada": "caducado",
    "ataque_suplantacion_con_certificado_propio": "no pertenece a 'ana'",
    "ataque_certificado_falso": "no está emitido por la autoridad",
    "ataque_password_de_firma_incorrecta": "Contraseña incorrecta",
    "ataque_modificar_saldo_cifrado": "manipulado",
    "ataque_copiar_saldo_de_otra_cuenta": "manipulado",
    "ataque_borrar_movimiento": "Faltan o sobran movimientos",
    "ataque_mover_movimiento": "HMAC no coincide",
    "ataque_modificar_justificante": "justificante alterado",
    "ataque_fuerza_bruta_login": "bloqueada",
}


@pytest.mark.parametrize("titulo, defensa, ataque", ATAQUES, ids=[a[2].__name__ for a in ATAQUES])
def test_el_ataque_se_rechaza(titulo, defensa, ataque):
    carpeta = tempfile.mkdtemp()
    try:
        with pytest.raises(ErrorBanco, match=MOTIVO_ESPERADO[ataque.__name__]):
            ataque(Escenario(carpeta))
    finally:
        shutil.rmtree(carpeta, ignore_errors=True)


def test_hay_un_motivo_esperado_para_cada_ataque():
    assert {a[2].__name__ for a in ATAQUES} == set(MOTIVO_ESPERADO)
