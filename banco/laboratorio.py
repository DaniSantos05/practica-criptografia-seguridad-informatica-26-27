"""
Laboratorio de ataques.

Cada función de este fichero intenta un ataque REAL contra el banco y comprueba
que se rechaza. Los ataques se ejecutan sobre un banco temporal, creado en una
carpeta aparte con dos clientes de prueba (Ana y Eva, la atacante), así que
nunca tocan los datos reales.

Se usa desde la web (página "Laboratorio de ataques") y desde los tests.
"""

import json
import secrets
import shutil
import tempfile
from contextlib import contextmanager
from datetime import timedelta

from banco import cripto
from banco.banco import Banco, ErrorBanco, ahora

PASSWORD_ANA = "Mi perro se llama Toby 2026"
PASSWORD_EVA = "Soy la atacante malvada 666"


class Escenario:
    """Banco temporal con dos clientas: Ana (víctima) y Eva (atacante)."""

    def __init__(self, carpeta):
        self.carpeta = carpeta
        self.banco = Banco(carpeta, secrets.token_hex(16), mostrar_registro=False)
        self.iban_ana = self.banco.registrar("ana", PASSWORD_ANA)
        self.iban_eva = self.banco.registrar("eva", PASSWORD_EVA)

    def orden_firmada_de_ana(self, importe=5000):
        """Una orden legítima de Ana (50 €) a Eva, firmada por Ana."""
        orden = self.banco.preparar_orden("ana", self.iban_eva, importe, "Pago de la cena")
        firma = self.banco.firmar_orden("ana", PASSWORD_ANA, orden)
        return orden, firma, self.banco.certificado_de("ana")

    @contextmanager
    def fichero_manipulado(self, nombre):
        """Permite editar un fichero de datos y lo restaura al terminar el ataque."""
        ruta = self.banco.almacen.ruta(nombre)
        copia = ruta.with_suffix(".copia")
        shutil.copy(ruta, copia)
        try:
            with ruta.open(encoding="utf-8") as fichero:
                datos = json.load(fichero)
            yield datos
        finally:
            shutil.move(copia, ruta)


def cambiar_un_byte(texto_hex):
    """Cambia el primer byte de un valor hexadecimal (simula una manipulación mínima)."""
    datos = bytearray.fromhex(texto_hex)
    datos[0] ^= 0x01
    return datos.hex()


# ---------------------------------------------------------------------------
# Ataques. Cada uno devuelve el error con el que el banco lo rechaza.
# Si el ataque funcionase (no hay error), se devuelve None.
# ---------------------------------------------------------------------------

def ataque_modificar_importe(e):
    """Eva intercepta una orden de Ana de 50 € y cambia el importe a 5.000 €."""
    orden, firma, certificado = e.orden_firmada_de_ana()
    orden["importe_centimos"] = 500_000
    e.banco.ejecutar_orden(orden, firma, certificado)


def ataque_firma_alterada(e):
    """Se modifica un solo byte de la firma de una orden válida."""
    orden, firma, certificado = e.orden_firmada_de_ana()
    e.banco.ejecutar_orden(orden, cambiar_un_byte(firma), certificado)


def ataque_replay(e):
    """Eva captura una orden válida de Ana y la envía otra vez para cobrar dos veces."""
    orden, firma, certificado = e.orden_firmada_de_ana()
    e.banco.ejecutar_orden(orden, firma, certificado)   # la primera vez es legítima
    e.banco.ejecutar_orden(orden, firma, certificado)   # la repetición debe rechazarse


def ataque_orden_caducada(e):
    """Se presenta una orden firmada hace una hora (bien firmada, pero antigua)."""
    orden = e.banco.preparar_orden("ana", e.iban_eva, 5000, "Orden antigua")
    orden["fecha"] = (ahora() - timedelta(hours=1)).isoformat()
    firma = e.banco.firmar_orden("ana", PASSWORD_ANA, orden)
    e.banco.ejecutar_orden(orden, firma, e.banco.certificado_de("ana"))


def ataque_suplantacion_con_certificado_propio(e):
    """
    Eva crea una orden que saca dinero de la cuenta de Ana y la firma con SU
    clave. Adjunta su certificado, que es válido... pero no es el de Ana.
    (Es el caso attacker.com de la práctica 4.)
    """
    orden = e.banco.preparar_orden("ana", e.iban_eva, 90_000, "Te robo")
    firma = e.banco.firmar_orden("eva", PASSWORD_EVA, orden)
    e.banco.ejecutar_orden(orden, firma, e.banco.certificado_de("eva"))


def ataque_certificado_falso(e):
    """
    Eva monta su propia autoridad de certificación y se fabrica un certificado
    a nombre de "ana". La firma es correcta, pero el certificado no lo ha
    emitido la CA del banco.
    """
    clave_ca_falsa = cripto.generar_par_claves()
    ca_falsa = cripto.crear_certificado_ca(clave_ca_falsa, "BancoSeguro - Autoridad de Certificacion")
    clave_eva = cripto.generar_par_claves()
    certificado_falso = cripto.emitir_certificado(clave_ca_falsa, ca_falsa, clave_eva.public_key(), "ana")
    orden = e.banco.preparar_orden("ana", e.iban_eva, 90_000, "Te robo")
    firma = cripto.firmar(clave_eva, cripto.json_canonico(orden))
    e.banco.ejecutar_orden(orden, firma, cripto.certificado_a_pem(certificado_falso))


def ataque_password_de_firma_incorrecta(e):
    """Alguien con acceso a la sesión de Ana intenta firmar sin saber su contraseña."""
    orden = e.banco.preparar_orden("ana", e.iban_eva, 5000, "Sin contraseña")
    e.banco.firmar_orden("ana", "no sé la contraseña", orden)


def ataque_modificar_saldo_cifrado(e):
    """Con acceso al disco, Eva cambia un byte del saldo cifrado de Ana."""
    with e.fichero_manipulado("cuentas.json") as cuentas:
        estado = cuentas[e.iban_ana]["estado_cifrado"]
        estado["cifrado"] = cambiar_un_byte(estado["cifrado"])
        e.banco.almacen.guardar("cuentas.json", cuentas)
        e.banco.consultar_cuenta("ana")


def ataque_copiar_saldo_de_otra_cuenta(e):
    """Eva copia el saldo cifrado de Ana en su propia cuenta (falla por el AAD)."""
    orden, firma, certificado = e.orden_firmada_de_ana()
    e.banco.ejecutar_orden(orden, firma, certificado)  # ahora Ana y Eva tienen saldos distintos
    with e.fichero_manipulado("cuentas.json") as cuentas:
        cuentas[e.iban_eva]["estado_cifrado"] = cuentas[e.iban_ana]["estado_cifrado"]
        e.banco.almacen.guardar("cuentas.json", cuentas)
        e.banco.consultar_cuenta("eva")


def ataque_borrar_movimiento(e):
    """Eva borra del fichero el último movimiento de su cuenta para ocultar un cargo."""
    orden, firma, certificado = e.orden_firmada_de_ana()
    e.banco.ejecutar_orden(orden, firma, certificado)
    with e.fichero_manipulado("movimientos.json") as movimientos:
        movimientos[e.iban_ana].pop()
        e.banco.almacen.guardar("movimientos.json", movimientos)
        e.banco.consultar_cuenta("ana")


def ataque_mover_movimiento(e):
    """Eva copia un movimiento de la cuenta de Ana (un ingreso) en la suya."""
    with e.fichero_manipulado("movimientos.json") as movimientos:
        movimientos[e.iban_eva][0] = movimientos[e.iban_ana][0]
        e.banco.almacen.guardar("movimientos.json", movimientos)
        e.banco.consultar_cuenta("eva")


def ataque_modificar_justificante(e):
    """Eva cambia el importe de un justificante de 50 € a 5.000 € para reclamar más dinero."""
    orden, firma, certificado = e.orden_firmada_de_ana()
    justificante = e.banco.ejecutar_orden(orden, firma, certificado)
    justificante["contenido"]["orden"]["importe_centimos"] = 500_000
    resultados, valido = e.banco.verificar_justificante(justificante)
    if not valido:
        fallos = [f"{texto}: {detalle}" for texto, correcta, detalle in resultados if not correcta]
        raise ErrorBanco("; ".join(fallos))


def ataque_fuerza_bruta_login(e):
    """Eva prueba contraseñas para entrar como Ana. Tras 5 fallos la cuenta se bloquea."""
    for intento in ["123456", "ana12345", "password", "qwerty", "ana2026"]:
        try:
            e.banco.iniciar_sesion("ana", intento)
        except ErrorBanco:
            pass
    # Aunque ahora acierte la contraseña, la cuenta está bloqueada
    e.banco.iniciar_sesion("ana", PASSWORD_ANA)


ATAQUES = [
    ("Modificar el importe de una orden firmada", "Integridad · firma digital", ataque_modificar_importe),
    ("Alterar un byte de la firma", "Firma digital", ataque_firma_alterada),
    ("Repetir una orden ya ejecutada (replay)", "Anti-replay", ataque_replay),
    ("Presentar una orden firmada hace una hora", "Anti-replay · caducidad", ataque_orden_caducada),
    ("Firmar en nombre de Ana con el certificado de Eva", "PKI · identidad", ataque_suplantacion_con_certificado_propio),
    ("Certificado de 'ana' emitido por una CA falsa", "PKI · cadena de confianza", ataque_certificado_falso),
    ("Firmar sin conocer la contraseña de Ana", "Protección de la clave privada", ataque_password_de_firma_incorrecta),
    ("Cambiar un byte del saldo cifrado en el disco", "Cifrado autenticado (AES-GCM)", ataque_modificar_saldo_cifrado),
    ("Copiar el saldo cifrado de otra cuenta", "AES-GCM · datos asociados (AAD)", ataque_copiar_saldo_de_otra_cuenta),
    ("Borrar un movimiento para ocultar un cargo", "HMAC encadenado", ataque_borrar_movimiento),
    ("Copiar un movimiento de otra cuenta", "HMAC encadenado", ataque_mover_movimiento),
    ("Modificar el importe de un justificante", "Firma del banco", ataque_modificar_justificante),
    ("Fuerza bruta contra la contraseña", "Autenticación · bloqueo", ataque_fuerza_bruta_login),
]


def ejecutar_laboratorio():
    """
    Ejecuta todos los ataques, cada uno en un banco temporal nuevo, y devuelve
    una lista de resultados para mostrar en la web.
    """
    resultados = []
    for titulo, defensa, ataque in ATAQUES:
        carpeta = tempfile.mkdtemp(prefix="laboratorio_")
        try:
            escenario = Escenario(carpeta)
            try:
                ataque(escenario)
                rechazado, mensaje = False, "¡El ataque ha funcionado!"
            except ErrorBanco as error:
                rechazado, mensaje = True, str(error)
            resultados.append({
                "titulo": titulo,
                "descripcion": " ".join(ataque.__doc__.split()),
                "defensa": defensa,
                "rechazado": rechazado,
                "mensaje": mensaje,
                "registro": list(reversed(escenario.banco.registro.ultimas(6))),
            })
        finally:
            shutil.rmtree(carpeta, ignore_errors=True)
    return resultados
