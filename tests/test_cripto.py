"""Pruebas de cada operación criptográfica de banco/cripto.py (positivas y negativas)."""

import os
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from banco import cripto


# --------------------------------------------------------------- contraseñas

def test_password_correcta_se_acepta():
    guardado = cripto.hash_password("una frase de prueba larga")
    assert cripto.verificar_password("una frase de prueba larga", guardado)


def test_password_incorrecta_se_rechaza():
    guardado = cripto.hash_password("una frase de prueba larga")
    assert not cripto.verificar_password("una frase de prueba larga.", guardado)


def test_misma_password_da_resumenes_distintos_gracias_a_la_sal():
    a = cripto.hash_password("password123456")
    b = cripto.hash_password("password123456")
    assert a["sal"] != b["sal"]
    assert a["hash"] != b["hash"]


def test_la_password_no_aparece_en_lo_guardado():
    guardado = cripto.hash_password("secreto-muy-secreto")
    assert "secreto" not in str(guardado)


# -------------------------------------------------------------- AES-256-GCM

def test_cifrar_y_descifrar():
    clave = os.urandom(32)
    paquete = cripto.cifrar(clave, b"saldo: 1000", b"cuenta:ES01")
    assert cripto.descifrar(clave, paquete, b"cuenta:ES01") == b"saldo: 1000"


def test_el_nonce_nunca_se_repite():
    clave = os.urandom(32)
    nonces = {cripto.cifrar(clave, b"mismo mensaje", b"")["nonce"] for _ in range(1000)}
    assert len(nonces) == 1000


def test_mismo_mensaje_da_cifrados_distintos():
    clave = os.urandom(32)
    assert cripto.cifrar(clave, b"hola", b"")["cifrado"] != cripto.cifrar(clave, b"hola", b"")["cifrado"]


def test_cifrado_modificado_se_rechaza():
    clave = os.urandom(32)
    paquete = cripto.cifrar(clave, b"saldo: 1000", b"")
    datos = bytearray.fromhex(paquete["cifrado"])
    datos[0] ^= 1
    paquete["cifrado"] = datos.hex()
    with pytest.raises(cripto.ErrorCriptografico):
        cripto.descifrar(clave, paquete, b"")


def test_tag_modificado_se_rechaza():
    clave = os.urandom(32)
    paquete = cripto.cifrar(clave, b"saldo: 1000", b"")
    datos = bytearray.fromhex(paquete["cifrado"])
    datos[-1] ^= 1  # el tag de 16 bytes va al final
    paquete["cifrado"] = datos.hex()
    with pytest.raises(cripto.ErrorCriptografico):
        cripto.descifrar(clave, paquete, b"")


def test_aad_distinto_se_rechaza():
    clave = os.urandom(32)
    paquete = cripto.cifrar(clave, b"saldo: 1000", b"cuenta:ES01")
    with pytest.raises(cripto.ErrorCriptografico):
        cripto.descifrar(clave, paquete, b"cuenta:ES02")


def test_clave_incorrecta_se_rechaza():
    paquete = cripto.cifrar(os.urandom(32), b"saldo: 1000", b"")
    with pytest.raises(cripto.ErrorCriptografico):
        cripto.descifrar(os.urandom(32), paquete, b"")


# ---------------------------------------------------------------- HKDF

def test_hkdf_da_subclaves_distintas_para_cada_uso():
    maestra = os.urandom(32)
    assert cripto.derivar_subclave(maestra, "cifrado") != cripto.derivar_subclave(maestra, "hmac")
    assert cripto.derivar_subclave(maestra, "cifrado") == cripto.derivar_subclave(maestra, "cifrado")


# ---------------------------------------------------------------- HMAC

def test_hmac_correcto_se_acepta():
    clave = os.urandom(32)
    assert cripto.verificar_hmac(clave, b"movimiento", cripto.calcular_hmac(clave, b"movimiento"))


def test_hmac_con_datos_modificados_se_rechaza():
    clave = os.urandom(32)
    mac = cripto.calcular_hmac(clave, b"importe=50")
    assert not cripto.verificar_hmac(clave, b"importe=5000", mac)


def test_hmac_con_otra_clave_se_rechaza():
    mac = cripto.calcular_hmac(os.urandom(32), b"movimiento")
    assert not cripto.verificar_hmac(os.urandom(32), b"movimiento", mac)


# -------------------------------------------------------------- firma ECDSA

def test_firma_valida_se_acepta():
    clave = cripto.generar_par_claves()
    firma = cripto.firmar(clave, b"orden")
    assert cripto.verificar_firma(clave.public_key(), b"orden", firma)


def test_firma_de_mensaje_modificado_se_rechaza():
    clave = cripto.generar_par_claves()
    firma = cripto.firmar(clave, b"Transfer 100 euros")
    assert not cripto.verificar_firma(clave.public_key(), b"Transfer 900 euros", firma)


def test_firma_alterada_se_rechaza():
    clave = cripto.generar_par_claves()
    firma = bytearray.fromhex(cripto.firmar(clave, b"orden"))
    firma[10] ^= 1
    assert not cripto.verificar_firma(clave.public_key(), b"orden", firma.hex())


def test_firma_con_otra_clave_se_rechaza():
    firma = cripto.firmar(cripto.generar_par_claves(), b"orden")
    assert not cripto.verificar_firma(cripto.generar_par_claves().public_key(), b"orden", firma)


def test_json_canonico_no_depende_del_orden_de_las_claves():
    assert cripto.json_canonico({"a": 1, "b": 2}) == cripto.json_canonico({"b": 2, "a": 1})


# ---------------------------------------------------- claves privadas cifradas

def test_clave_privada_cifrada_se_recupera_con_la_clave_correcta():
    privada = cripto.generar_par_claves()
    kek = os.urandom(32)
    paquete = cripto.proteger_clave_privada(privada, kek, b"ana")
    recuperada = cripto.recuperar_clave_privada(paquete, kek, b"ana")
    assert recuperada.private_numbers() == privada.private_numbers()


def test_clave_privada_no_se_recupera_con_otra_clave():
    paquete = cripto.proteger_clave_privada(cripto.generar_par_claves(), os.urandom(32), b"ana")
    with pytest.raises(cripto.ErrorCriptografico):
        cripto.recuperar_clave_privada(paquete, os.urandom(32), b"ana")


# ---------------------------------------------------------- certificados

@pytest.fixture
def ca():
    clave = cripto.generar_par_claves()
    return clave, cripto.crear_certificado_ca(clave, "CA de prueba")


def test_certificado_valido_se_acepta(ca):
    clave_ca, cert_ca = ca
    cert = cripto.emitir_certificado(clave_ca, cert_ca, cripto.generar_par_claves().public_key(), "ana")
    cripto.verificar_certificado(cert, cert_ca, "ana")  # no lanza error


def test_certificado_de_otra_persona_se_rechaza(ca):
    clave_ca, cert_ca = ca
    cert = cripto.emitir_certificado(clave_ca, cert_ca, cripto.generar_par_claves().public_key(), "eva")
    with pytest.raises(cripto.ErrorCriptografico, match="no pertenece"):
        cripto.verificar_certificado(cert, cert_ca, "ana")


def test_certificado_de_otra_ca_se_rechaza(ca):
    _, cert_ca = ca
    clave_falsa = cripto.generar_par_claves()
    ca_falsa = cripto.crear_certificado_ca(clave_falsa, "CA de prueba")  # mismo nombre, otra clave
    cert = cripto.emitir_certificado(clave_falsa, ca_falsa, cripto.generar_par_claves().public_key(), "ana")
    with pytest.raises(cripto.ErrorCriptografico, match="no está emitido"):
        cripto.verificar_certificado(cert, cert_ca, "ana")


def test_certificado_caducado_se_rechaza(ca):
    clave_ca, cert_ca = ca
    hace_un_ano = datetime.now(timezone.utc) - timedelta(days=365)
    # Certificado correcto en todo salvo las fechas: fue válido el año pasado, durante 30 días
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ana")]))
        .issuer_name(cert_ca.subject)
        .public_key(cripto.generar_par_claves().public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(hace_un_ano)
        .not_valid_after(hace_un_ano + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(clave_ca, hashes.SHA256())
    )
    with pytest.raises(cripto.ErrorCriptografico, match="caducado"):
        cripto.verificar_certificado(cert, cert_ca, "ana")


def test_certificado_de_ca_no_sirve_para_firmar_documentos(ca):
    clave_ca, cert_ca = ca
    with pytest.raises(cripto.ErrorCriptografico, match="no pertenece|no está autorizado"):
        cripto.verificar_certificado(cert_ca, cert_ca, "CA de prueba")
