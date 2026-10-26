"""
PUNTO 5 · Generación y almacenamiento de claves (y certificados X.509).
Pruebas de banco/cripto/punto5_claves.py, banco/cripto/punto5_certificados.py
y de la frase maestra del banco.
"""

import os
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from banco.banco import Banco, ErrorBanco, FraseMaestraIncorrecta
from banco.cripto import punto4_firma as firmas
from banco.cripto import punto5_certificados as certificados
from banco.cripto import punto5_claves as claves
from banco.cripto.comun import ErrorCriptografico, generar_sal
from tests.conftest import PASSWORD_ANA, iban_de


@pytest.fixture
def ca():
    clave = firmas.generar_par_claves()
    return clave, certificados.crear_certificado_ca(clave, "CA de prueba")


def certificado_para(ca, nombre):
    clave_ca, cert_ca = ca
    return certificados.emitir_certificado(clave_ca, cert_ca, firmas.generar_par_claves().public_key(), nombre)

# ------------------------------------------------------------- casos correctos


def test_la_misma_password_y_sal_dan_la_misma_clave():
    sal = generar_sal()
    assert claves.derivar_clave_de_password("frase", sal) == claves.derivar_clave_de_password("frase", sal)
    assert len(claves.derivar_clave_de_password("frase", sal)) == 32  # 256 bits


def test_hkdf_da_subclaves_distintas_para_cada_uso():
    maestra = os.urandom(32)
    assert claves.derivar_subclave(maestra, "cifrado") != claves.derivar_subclave(maestra, "hmac")


def test_clave_privada_cifrada_se_recupera_con_la_clave_correcta():
    privada = firmas.generar_par_claves()
    kek = os.urandom(32)
    paquete = claves.proteger_clave_privada(privada, kek, b"ana")
    assert claves.recuperar_clave_privada(paquete, kek, b"ana").private_numbers() == privada.private_numbers()


def test_frase_maestra_correcta_recupera_los_datos(tmp_path):
    Banco(tmp_path, "frase maestra correcta", mostrar_registro=False).registrar("ana", PASSWORD_ANA)
    otra_vez = Banco(tmp_path, "frase maestra correcta", mostrar_registro=False)
    assert otra_vez.consultar_cuenta("ana")["saldo_centimos"] == 100_000


def test_ninguna_clave_ni_secreto_se_guarda_en_claro(banco_con_clientes, tmp_path):
    for fichero in tmp_path.glob("*.json"):
        texto = fichero.read_text(encoding="utf-8")
        assert "PRIVATE KEY" not in texto
        assert "frase maestra de los tests" not in texto
        assert PASSWORD_ANA not in texto


def test_certificado_valido_se_acepta(ca):
    certificados.verificar_certificado(certificado_para(ca, "ana"), ca[1], "ana")  # no lanza error


def test_cada_cliente_recibe_un_certificado_de_la_ca_del_banco(banco_con_clientes):
    certificado = certificados.pem_a_certificado(banco_con_clientes.certificado_de("ana"))
    certificados.verificar_certificado(certificado, banco_con_clientes.certificado_ca, "ana")

# --------------------------------------------------------------- casos de error


def test_clave_privada_no_se_recupera_con_otra_clave():
    paquete = claves.proteger_clave_privada(firmas.generar_par_claves(), os.urandom(32), b"ana")
    with pytest.raises(ErrorCriptografico):
        claves.recuperar_clave_privada(paquete, os.urandom(32), b"ana")


def test_frase_maestra_incorrecta_impide_arrancar(tmp_path):
    Banco(tmp_path, "frase maestra correcta", mostrar_registro=False)
    with pytest.raises(FraseMaestraIncorrecta):
        Banco(tmp_path, "frase maestra INCORRECTA", mostrar_registro=False)


def test_firmar_con_password_incorrecta_es_imposible(banco_con_clientes):
    with pytest.raises(ErrorBanco, match="Contraseña incorrecta"):
        banco_con_clientes.transferir("ana", "no es la contraseña", iban_de(banco_con_clientes, "luis"), 100, "x")


def test_certificado_de_otra_persona_se_rechaza(ca):
    with pytest.raises(ErrorCriptografico, match="no pertenece"):
        certificados.verificar_certificado(certificado_para(ca, "eva"), ca[1], "ana")


def test_certificado_de_otra_ca_se_rechaza(ca):
    clave_falsa = firmas.generar_par_claves()
    ca_falsa = certificados.crear_certificado_ca(clave_falsa, "CA de prueba")  # mismo nombre, otra clave
    with pytest.raises(ErrorCriptografico, match="no está emitido"):
        certificados.verificar_certificado(certificado_para((clave_falsa, ca_falsa), "ana"), ca[1], "ana")


def test_certificado_caducado_se_rechaza(ca):
    clave_ca, cert_ca = ca
    hace_un_ano = datetime.now(timezone.utc) - timedelta(days=365)
    # Correcto en todo salvo las fechas: fue válido el año pasado, durante 30 días
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ana")]))
        .issuer_name(cert_ca.subject)
        .public_key(firmas.generar_par_claves().public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(hace_un_ano)
        .not_valid_after(hace_un_ano + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(clave_ca, hashes.SHA256())
    )
    with pytest.raises(ErrorCriptografico, match="caducado"):
        certificados.verificar_certificado(cert, cert_ca, "ana")


def test_certificado_de_ca_no_sirve_para_firmar_documentos(ca):
    with pytest.raises(ErrorCriptografico, match="no está autorizado"):
        certificados.verificar_certificado(ca[1], ca[1], "CA de prueba")
