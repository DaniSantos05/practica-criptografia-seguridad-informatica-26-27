"""
Lógica del banco: registro, inicio de sesión, cuentas, transferencias y justificantes.

Este fichero NO implementa criptografía: usa las funciones de la carpeta
banco/cripto/ (un archivo por cada punto del enunciado) y anota cada operación
en el registro de seguridad con la etiqueta de su punto (P1 ... P5).

Ficheros de datos (carpeta "datos/"):
  config_banco.json  -> claves del banco (cifradas) y certificados
  usuarios.json      -> resumen Argon2id de la contraseña, clave de firma cifrada y certificado
  cuentas.json       -> estado de cada cuenta (saldo...) cifrado con AES-256-GCM
  movimientos.json   -> movimientos cifrados con AES-256-GCM + HMAC encadenado
  justificantes.json -> justificantes firmados por el banco (cifrados)
"""

import re
import secrets
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from banco.almacen import Almacen
from banco.cripto import comun
from banco.cripto import punto1_autenticacion as autenticacion
from banco.cripto import punto2_cifrado as cifrado
from banco.cripto import punto3_integridad as integridad
from banco.cripto import punto4_firma as firmas
from banco.cripto import punto5_certificados as certificados
from banco.cripto import punto5_claves as claves
from banco.registro import RegistroSeguridad

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------

SALDO_INICIAL_CENTIMOS = 100_000          # 1.000,00 € de regalo al abrir la cuenta
MAX_IMPORTE_CENTIMOS = 10_000_000         # 100.000,00 € como máximo por transferencia
MAX_INTENTOS_LOGIN = 5                    # intentos fallidos antes de bloquear
MINUTOS_BLOQUEO = 5
MINUTOS_VALIDEZ_ORDEN = 5                 # una orden firmada caduca a los 5 minutos
LONGITUD_MAXIMA_CONCEPTO = 140

PATRON_USUARIO = re.compile(r"^[a-z0-9_]{3,20}$")
PATRON_IBAN = re.compile(r"^ES\d{22}$")

NOMBRE_CA = "BancoSeguro - Autoridad de Certificacion"
NOMBRE_FIRMA_BANCO = "BancoSeguro - Firma de justificantes"

HMAC_INICIAL = "0" * 64   # "HMAC anterior" del primer movimiento de cada cuenta
MENSAJE_LOGIN_FALLIDO = "Usuario o contraseña incorrectos"  # igual en ambos casos


class ErrorBanco(Exception):
    """Error que se muestra al usuario (datos no válidos, saldo insuficiente...)."""


class FraseMaestraIncorrecta(ErrorBanco):
    """La frase maestra introducida al arrancar no es la correcta."""


class ErrorIntegridad(ErrorBanco):
    """Los datos guardados han sido manipulados."""


class OrdenRechazada(ErrorBanco):
    """Una orden de transferencia no ha superado las comprobaciones."""


def ahora():
    return datetime.now(timezone.utc)


def euros(centimos):
    """Formatea céntimos como texto: 125050 -> '1.250,50 €'."""
    signo = "-" if centimos < 0 else ""
    texto = f"{abs(centimos) / 100:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    return f"{signo}{texto} €"


class Banco:
    def __init__(self, carpeta_datos, frase_maestra, mostrar_registro=True):
        self.almacen = Almacen(carpeta_datos)
        self.registro = RegistroSeguridad(Path(carpeta_datos) / "registro_seguridad.log", mostrar_registro)
        # La web atiende varias peticiones a la vez: el cerrojo evita que dos
        # transferencias modifiquen los ficheros al mismo tiempo.
        self._cerrojo = threading.Lock()

        config = self.almacen.leer("config_banco.json", None)
        if config is None:
            self._crear_banco(frase_maestra)
        else:
            self._abrir_banco(frase_maestra, config)

    # =======================================================================
    # PUNTO 5 · Arranque: claves del banco (derivadas de la frase maestra)
    # =======================================================================

    def _derivar_claves(self, frase_maestra, sal):
        """
        La clave maestra NO se guarda en ningún fichero: se calcula a partir de
        la frase maestra que se escribe al arrancar. De ella salen dos subclaves
        independientes (una para cifrar y otra para el HMAC).
        """
        clave_maestra = claves.derivar_clave_de_password(frase_maestra, sal)
        self._clave_datos = claves.derivar_subclave(clave_maestra, "cifrado de datos")
        self._clave_hmac = claves.derivar_subclave(clave_maestra, "hmac de movimientos")
        self.registro.anotar(
            "P5-CLAVES",
            "Clave maestra derivada de la frase con Argon2id (256 bits). Subclaves derivadas "
            "con HKDF-SHA256: cifrado AES-256-GCM (256 bits) y HMAC-SHA256 (256 bits)",
        )

    def _crear_banco(self, frase_maestra):
        """Primera ejecución: crea las claves y la autoridad de certificación del banco."""
        if len(frase_maestra) < autenticacion.LONGITUD_MINIMA_PASSWORD:
            raise ErrorBanco(f"La frase maestra debe tener al menos {autenticacion.LONGITUD_MINIMA_PASSWORD} "
                             "caracteres")

        sal = comun.generar_sal()
        self._derivar_claves(frase_maestra, sal)

        # Texto conocido cifrado: al arrancar, si se descifra bien, la frase es correcta
        comprobacion = cifrado.cifrar(self._clave_datos, b"BancoSeguro", aad=b"comprobacion frase maestra")

        # Autoridad de certificación (CA) del banco: certifica las claves de los clientes
        clave_ca = firmas.generar_par_claves()
        certificado_ca = certificados.crear_certificado_ca(clave_ca, NOMBRE_CA)

        # Clave con la que el banco firma justificantes. Es distinta de la de la CA:
        # cada clave para un único uso.
        clave_firma = firmas.generar_par_claves()
        certificado_firma = certificados.emitir_certificado(
            clave_ca, certificado_ca, clave_firma.public_key(), NOMBRE_FIRMA_BANCO, dias=2 * 365
        )

        config = {
            "sal_frase_maestra": sal.hex(),
            "comprobacion": comprobacion,
            "certificado_ca": certificados.certificado_a_pem(certificado_ca),
            "clave_ca_cifrada": claves.proteger_clave_privada(clave_ca, self._clave_datos, b"clave privada CA"),
            "certificado_firma": certificados.certificado_a_pem(certificado_firma),
            "clave_firma_cifrada": claves.proteger_clave_privada(
                clave_firma, self._clave_datos, b"clave privada firma banco"
            ),
        }
        self.almacen.guardar("config_banco.json", config)
        self.registro.anotar(
            "P5-PKI",
            "Creada la CA del banco (ECDSA P-256, certificado X.509 autofirmado, 5 años) y la clave de "
            "firma de justificantes (ECDSA P-256, certificado emitido por la CA). Claves privadas "
            "guardadas en PKCS#8 cifradas con AES-256-GCM",
        )
        self._cargar_claves_banco(config)

    def _abrir_banco(self, frase_maestra, config):
        """Arranques siguientes: comprueba la frase y carga las claves del banco."""
        self._derivar_claves(frase_maestra, bytes.fromhex(config["sal_frase_maestra"]))
        try:
            cifrado.descifrar(self._clave_datos, config["comprobacion"], aad=b"comprobacion frase maestra")
        except comun.ErrorCriptografico:
            self.registro.anotar("P5-CLAVES", "Frase maestra INCORRECTA: el tag AES-GCM de comprobación no coincide")
            raise FraseMaestraIncorrecta("La frase maestra no es correcta") from None
        self._cargar_claves_banco(config)
        self.registro.anotar("P5-CLAVES", "Frase maestra correcta. Claves del banco descifradas en memoria")

    def _cargar_claves_banco(self, config):
        self.certificado_ca = certificados.pem_a_certificado(config["certificado_ca"])
        self.certificado_firma = certificados.pem_a_certificado(config["certificado_firma"])
        self._clave_ca = claves.recuperar_clave_privada(
            config["clave_ca_cifrada"], self._clave_datos, b"clave privada CA"
        )
        self._clave_firma = claves.recuperar_clave_privada(
            config["clave_firma_cifrada"], self._clave_datos, b"clave privada firma banco"
        )

    # =======================================================================
    # PUNTO 1 · Registro e inicio de sesión
    # =======================================================================

    def registrar(self, usuario, password):
        """Da de alta un cliente: contraseña, claves de firma, certificado y cuenta."""
        usuario = usuario.strip().lower()
        if not PATRON_USUARIO.fullmatch(usuario):
            raise ErrorBanco("El usuario debe tener de 3 a 20 caracteres: letras minúsculas, números o _")
        problema = autenticacion.problema_de_password(usuario, password)
        if problema:
            self.registro.anotar("P1-AUTENTICACION", f"Registro RECHAZADO para '{usuario}': {problema}")
            raise ErrorBanco(problema)

        with self._cerrojo:
            usuarios = self.almacen.leer("usuarios.json", {})
            if usuario in usuarios:
                raise ErrorBanco("Ese nombre de usuario ya existe")

            # 1) Contraseña: solo se guarda su resumen Argon2id (con sal)
            datos_password = autenticacion.hash_password(password)
            self.registro.anotar(
                "P1-AUTENTICACION",
                f"Registro de '{usuario}': contraseña guardada como Argon2id (t={autenticacion.ARGON2_ITERACIONES}, "
                f"m={autenticacion.ARGON2_MEMORIA_KIB // 1024} MiB, p={autenticacion.ARGON2_HILOS}, sal de 128 bits)",
            )

            # 2) Par de claves de firma del cliente. La privada se cifra con una
            #    clave derivada de SU contraseña: el banco no puede usarla sin ella.
            clave_privada = firmas.generar_par_claves()
            sal_clave = comun.generar_sal()
            clave_proteccion = claves.derivar_clave_de_password(password, sal_clave)
            clave_privada_cifrada = claves.proteger_clave_privada(clave_privada, clave_proteccion, usuario.encode())

            # 3) La CA del banco certifica que esa clave pública es de este cliente
            certificado = certificados.emitir_certificado(
                self._clave_ca, self.certificado_ca, clave_privada.public_key(), usuario
            )
            self.registro.anotar(
                "P5-PKI",
                f"Par de claves ECDSA P-256 generado para '{usuario}'. Clave privada cifrada con AES-256-GCM "
                f"(clave derivada de su contraseña con Argon2id). Certificado X.509 emitido por la CA (1 año)",
            )

            # 4) Cuenta bancaria con el saldo de bienvenida
            cuentas = self.almacen.leer("cuentas.json", {})
            movimientos = self.almacen.leer("movimientos.json", {})
            iban = self._nuevo_iban(cuentas)
            self._guardar_estado_cuenta(cuentas, iban, {"saldo_centimos": 0, "num_movimientos": 0,
                                                        "ultimo_hmac": HMAC_INICIAL})
            cuentas[iban]["titular"] = usuario
            self._anadir_movimiento(cuentas, movimientos, iban, {
                "fecha": ahora().isoformat(),
                "tipo": "Saldo de bienvenida",
                "importe_centimos": SALDO_INICIAL_CENTIMOS,
                "contraparte": "BancoSeguro",
                "concepto": "Apertura de cuenta",
                "id_orden": None,
            })

            usuarios[usuario] = {
                "password": datos_password,
                "intentos_fallidos": 0,
                "bloqueado_hasta": None,
                "iban": iban,
                "sal_clave_firma": sal_clave.hex(),
                "clave_firma_cifrada": clave_privada_cifrada,
                "certificado": certificados.certificado_a_pem(certificado),
            }
            self.almacen.guardar("usuarios.json", usuarios)
            self.almacen.guardar("cuentas.json", cuentas)
            self.almacen.guardar("movimientos.json", movimientos)
            return iban

    def iniciar_sesion(self, usuario, password):
        """Comprueba usuario y contraseña. Bloquea tras varios intentos fallidos."""
        usuario = usuario.strip().lower()
        with self._cerrojo:
            usuarios = self.almacen.leer("usuarios.json", {})
            datos = usuarios.get(usuario)

            if datos is None:
                # Se calcula igualmente un Argon2id para tardar lo mismo: así el
                # tiempo de respuesta no revela qué usuarios existen.
                autenticacion.hash_password(password)
                self.registro.anotar("P1-AUTENTICACION", "Inicio de sesión RECHAZADO (usuario inexistente)")
                raise ErrorBanco(MENSAJE_LOGIN_FALLIDO)

            if datos["bloqueado_hasta"] and ahora() < datetime.fromisoformat(datos["bloqueado_hasta"]):
                self.registro.anotar("P1-AUTENTICACION", f"Inicio de sesión RECHAZADO: '{usuario}' está bloqueado")
                raise ErrorBanco("Cuenta bloqueada temporalmente por demasiados intentos fallidos. "
                                 f"Inténtalo de nuevo en {MINUTOS_BLOQUEO} minutos.")

            if not autenticacion.verificar_password(password, datos["password"]):
                datos["intentos_fallidos"] += 1
                if datos["intentos_fallidos"] >= MAX_INTENTOS_LOGIN:
                    datos["bloqueado_hasta"] = (ahora() + timedelta(minutes=MINUTOS_BLOQUEO)).isoformat()
                    datos["intentos_fallidos"] = 0
                    self.registro.anotar("P1-AUTENTICACION", f"'{usuario}' BLOQUEADO {MINUTOS_BLOQUEO} minutos "
                                                          f"tras {MAX_INTENTOS_LOGIN} intentos fallidos")
                self.almacen.guardar("usuarios.json", usuarios)
                self.registro.anotar("P1-AUTENTICACION", f"Inicio de sesión RECHAZADO para '{usuario}': "
                                                      "la contraseña no coincide con el resumen Argon2id")
                raise ErrorBanco(MENSAJE_LOGIN_FALLIDO)

            datos["intentos_fallidos"] = 0
            datos["bloqueado_hasta"] = None
            self.almacen.guardar("usuarios.json", usuarios)
            self.registro.anotar("P1-AUTENTICACION", f"Inicio de sesión CORRECTO de '{usuario}' (Argon2id verificado)")
            return usuario

    # =======================================================================
    # PUNTOS 2 y 3 · Cuentas y movimientos (cifrado AES-GCM + HMAC encadenado)
    # =======================================================================

    def _nuevo_iban(self, cuentas):
        """IBAN ficticio con formato español (ES + 22 dígitos)."""
        while True:
            iban = "ES" + "".join(str(secrets.randbelow(10)) for _ in range(22))
            if iban not in cuentas:
                return iban

    def _guardar_estado_cuenta(self, cuentas, iban, estado):
        """
        El estado de la cuenta (saldo, número de movimientos y HMAC del último)
        se guarda cifrado. El IBAN va como dato asociado (AAD): si alguien copia
        el saldo cifrado de otra cuenta en la suya, el descifrado falla.
        """
        cuentas.setdefault(iban, {})
        cuentas[iban]["estado_cifrado"] = cifrado.cifrar_json(self._clave_datos, estado, ("cuenta:" + iban).encode())

    def _leer_estado_cuenta(self, cuentas, iban):
        try:
            return cifrado.descifrar_json(self._clave_datos, cuentas[iban]["estado_cifrado"], ("cuenta:" + iban).encode())
        except (comun.ErrorCriptografico, KeyError) as error:
            raise ErrorIntegridad(f"El estado de la cuenta {iban} ha sido manipulado (falla el tag AES-GCM)") from error

    def _datos_para_hmac(self, iban, movimiento, hmac_anterior):
        """
        Datos sobre los que se calcula el HMAC-SHA256 de un movimiento: el
        movimiento ya cifrado (Encrypt-then-MAC), el IBAN y el HMAC del
        movimiento anterior. Al encadenarlos, si se borra,
        se cambia de orden o se mueve un movimiento, la cadena se rompe.
        """
        return comun.json_canonico({
            "iban": iban,
            "id": movimiento["id"],
            "cifrado": movimiento["cifrado"],
            "hmac_anterior": hmac_anterior,
        })

    def _anadir_movimiento(self, cuentas, movimientos, iban, datos_movimiento):
        """Cifra un movimiento nuevo, lo encadena con HMAC y actualiza el saldo."""
        estado = self._leer_estado_cuenta(cuentas, iban)
        id_movimiento = secrets.token_hex(8)
        movimiento = {
            "id": id_movimiento,
            "cifrado": cifrado.cifrar_json(self._clave_datos, datos_movimiento,
                                          f"movimiento:{iban}:{id_movimiento}".encode()),
        }
        movimiento["hmac"] = integridad.calcular_hmac(
            self._clave_hmac, self._datos_para_hmac(iban, movimiento, estado["ultimo_hmac"])
        )
        movimientos.setdefault(iban, []).append(movimiento)

        estado["saldo_centimos"] += datos_movimiento["importe_centimos"]
        estado["num_movimientos"] += 1
        estado["ultimo_hmac"] = movimiento["hmac"]
        self._guardar_estado_cuenta(cuentas, iban, estado)
        self.registro.anotar("P2-CIFRADO", f"Movimiento de la cuenta ...{iban[-4:]} cifrado con AES-256-GCM "
                                           "(clave de 256 bits, nonce nuevo de 96 bits, AAD = IBAN + id)")
        self.registro.anotar("P3-MAC", f"Movimiento de la cuenta ...{iban[-4:]} sellado con HMAC-SHA256 "
                                       "encadenado al anterior (clave de 256 bits)")

    def _verificar_cuenta(self, cuentas, movimientos, iban):
        """
        Comprueba que NADA de la cuenta ha sido manipulado y devuelve el estado y
        los movimientos descifrados. Si algo falla lanza ErrorIntegridad y los
        datos no se usan.
        """
        estado = self._leer_estado_cuenta(cuentas, iban)
        lista = movimientos.get(iban, [])
        if len(lista) != estado["num_movimientos"]:
            raise ErrorIntegridad(f"Faltan o sobran movimientos en la cuenta {iban}")

        hmac_anterior = HMAC_INICIAL
        suma = 0
        descifrados = []
        for movimiento in lista:
            try:
                datos_hmac = self._datos_para_hmac(iban, movimiento, hmac_anterior)
                hmac_correcto = integridad.verificar_hmac(self._clave_hmac, datos_hmac, movimiento["hmac"])
            except (KeyError, TypeError):
                hmac_correcto = False
            if not hmac_correcto:
                raise ErrorIntegridad(f"Un movimiento de la cuenta {iban} ha sido modificado, movido o "
                                      "reordenado (el HMAC no coincide)")
            try:
                datos = cifrado.descifrar_json(self._clave_datos, movimiento["cifrado"],
                                              f"movimiento:{iban}:{movimiento['id']}".encode())
            except comun.ErrorCriptografico as error:
                raise ErrorIntegridad(f"Un movimiento de la cuenta {iban} no se puede descifrar") from error
            suma += datos["importe_centimos"]
            descifrados.append(datos)
            hmac_anterior = movimiento["hmac"]

        if not comun.iguales(hmac_anterior, estado["ultimo_hmac"]):
            raise ErrorIntegridad(f"Se ha eliminado el último movimiento de la cuenta {iban}")
        if suma != estado["saldo_centimos"]:
            raise ErrorIntegridad(f"El saldo de la cuenta {iban} no cuadra con sus movimientos")

        self.registro.anotar(
            "P3-MAC",
            f"Cuenta ...{iban[-4:]} verificada: {len(lista)} movimiento(s) con HMAC-SHA256 correcto y "
            "tags AES-GCM válidos",
        )
        return estado, descifrados

    def consultar_cuenta(self, usuario):
        """Saldo y movimientos de un cliente (verificando antes su integridad)."""
        usuarios = self.almacen.leer("usuarios.json", {})
        iban = usuarios[usuario]["iban"]
        cuentas = self.almacen.leer("cuentas.json", {})
        movimientos = self.almacen.leer("movimientos.json", {})
        estado, lista = self._verificar_cuenta(cuentas, movimientos, iban)
        return {"iban": iban, "saldo_centimos": estado["saldo_centimos"], "movimientos": list(reversed(lista))}

    def listar_destinatarios(self, usuario):
        """Otros clientes a los que se puede transferir (usuario e IBAN)."""
        usuarios = self.almacen.leer("usuarios.json", {})
        return [(nombre, datos["iban"]) for nombre, datos in sorted(usuarios.items()) if nombre != usuario]

    def certificado_de(self, usuario):
        return self.almacen.leer("usuarios.json", {})[usuario]["certificado"]

    # =======================================================================
    # PUNTO 4 · Transferencias: orden -> firma del cliente -> verificación -> ejecución
    # =======================================================================

    def preparar_orden(self, usuario, iban_destino, importe_centimos, concepto):
        """Crea la orden de transferencia que el cliente va a firmar."""
        usuarios = self.almacen.leer("usuarios.json", {})
        return {
            # Identificador aleatorio y único: impide ejecutar dos veces la misma orden (replay)
            "id_orden": secrets.token_hex(16),
            "ordenante": usuario,
            "iban_origen": usuarios[usuario]["iban"],
            "iban_destino": iban_destino.replace(" ", "").upper(),
            "importe_centimos": importe_centimos,
            "concepto": concepto.strip(),
            # La fecha va dentro de lo firmado: no se puede cambiar sin romper la firma
            "fecha": ahora().isoformat(),
        }

    def firmar_orden(self, usuario, password, orden):
        """
        El cliente firma la orden con SU clave privada. Para usarla hay que
        descifrarla con una clave derivada de su contraseña: sin la contraseña
        nadie (ni el propio banco) puede firmar en su nombre.
        """
        datos = self.almacen.leer("usuarios.json", {})[usuario]
        clave_proteccion = claves.derivar_clave_de_password(password, bytes.fromhex(datos["sal_clave_firma"]))
        try:
            clave_privada = claves.recuperar_clave_privada(datos["clave_firma_cifrada"], clave_proteccion,
                                                           usuario.encode())
        except comun.ErrorCriptografico:
            self.registro.anotar("P4-FIRMA", f"No se pudo descifrar la clave de firma de '{usuario}': "
                                          "contraseña incorrecta (tag AES-GCM no válido)")
            raise ErrorBanco("Contraseña incorrecta: no se ha podido desbloquear tu clave de firma") from None
        firma = firmas.firmar(clave_privada, comun.json_canonico(orden))
        self.registro.anotar("P4-FIRMA", f"Orden {orden['id_orden'][:8]}… firmada por '{usuario}' con ECDSA P-256 "
                                      "+ SHA-256 (clave de 256 bits)")
        return firma

    def _rechazar(self, motivo):
        self.registro.anotar("RECHAZO", f"Orden RECHAZADA: {motivo}")
        raise OrdenRechazada(motivo)

    def ejecutar_orden(self, orden, firma, certificado_pem):
        """
        El banco recibe (orden, firma, certificado) y solo ejecuta la
        transferencia si TODAS las comprobaciones son correctas.
        Devuelve el justificante firmado por el banco.
        """
        with self._cerrojo:
            if not isinstance(orden, dict):
                self._rechazar("la orden no tiene un formato válido")
            ordenante = orden.get("ordenante")

            # 1. Certificado: emitido por nuestra CA, vigente y del ordenante
            try:
                certificado = certificados.pem_a_certificado(certificado_pem)
                certificados.verificar_certificado(certificado, self.certificado_ca, ordenante)
            except comun.ErrorCriptografico as error:
                self._rechazar(f"certificado no válido: {error}")
            self.registro.anotar("P5-PKI", f"Certificado de '{ordenante}' válido: firmado por la CA del banco, "
                                        "vigente y con uso de firma digital")

            # 2. Firma: la orden no ha cambiado desde que el cliente la firmó
            if not firmas.verificar_firma(certificado.public_key(), comun.json_canonico(orden), firma):
                self._rechazar("la firma ECDSA no es válida (la orden o la firma han sido modificadas)")
            self.registro.anotar("P4-FIRMA", f"Firma ECDSA P-256 de la orden {orden['id_orden'][:8]}… VERIFICADA")

            # 3. Contenido de la orden
            usuarios = self.almacen.leer("usuarios.json", {})
            cuentas = self.almacen.leer("cuentas.json", {})
            movimientos = self.almacen.leer("movimientos.json", {})
            importe = orden.get("importe_centimos")
            if usuarios.get(ordenante, {}).get("iban") != orden.get("iban_origen"):
                self._rechazar("el ordenante no es el titular de la cuenta de origen")
            if orden.get("iban_destino") not in cuentas:
                self._rechazar("la cuenta de destino no existe")
            if orden["iban_destino"] == orden["iban_origen"]:
                self._rechazar("no se puede transferir a la misma cuenta")
            if not isinstance(importe, int) or not 0 < importe <= MAX_IMPORTE_CENTIMOS:
                self._rechazar("importe no válido")

            # 4. Caducidad: una orden antigua no se acepta aunque esté bien firmada
            try:
                fecha = datetime.fromisoformat(orden["fecha"])
            except (KeyError, TypeError, ValueError):
                fecha = None
            if fecha is None or fecha.tzinfo is None:
                self._rechazar("fecha de la orden no válida")
            if not timedelta(minutes=-1) <= ahora() - fecha <= timedelta(minutes=MINUTOS_VALIDEZ_ORDEN):
                self._rechazar(f"la orden ha caducado (validez de {MINUTOS_VALIDEZ_ORDEN} minutos)")

            # 5. Integridad de las dos cuentas antes de tocarlas
            estado_origen, movimientos_origen = self._verificar_cuenta(cuentas, movimientos, orden["iban_origen"])
            self._verificar_cuenta(cuentas, movimientos, orden["iban_destino"])

            # 6. Anti-replay: esta orden no se ha ejecutado antes
            if any(m.get("id_orden") == orden["id_orden"] for m in movimientos_origen):
                self._rechazar("esta orden ya se ejecutó antes (ataque de repetición / replay)")

            # 7. Saldo suficiente
            if estado_origen["saldo_centimos"] < importe:
                self._rechazar("saldo insuficiente")

            # 8. Ejecución: un cargo en la cuenta de origen y un abono en la de destino
            fecha_ejecucion = ahora().isoformat()
            datos_comunes = {"fecha": fecha_ejecucion, "concepto": orden["concepto"], "id_orden": orden["id_orden"]}
            self._anadir_movimiento(cuentas, movimientos, orden["iban_origen"], {
                **datos_comunes, "tipo": "Transferencia enviada", "importe_centimos": -importe,
                "contraparte": orden["iban_destino"]})
            self._anadir_movimiento(cuentas, movimientos, orden["iban_destino"], {
                **datos_comunes, "tipo": "Transferencia recibida", "importe_centimos": importe,
                "contraparte": orden["iban_origen"]})

            # 9. Justificante firmado por el banco
            justificante = self._crear_justificante(orden, firma, certificado_pem, fecha_ejecucion)
            self.almacen.guardar("cuentas.json", cuentas)
            self.almacen.guardar("movimientos.json", movimientos)
            self.registro.anotar("ORDEN", f"Transferencia de {euros(importe)} EJECUTADA "
                                          f"({orden['iban_origen'][-4:]} -> {orden['iban_destino'][-4:]})")
            return justificante

    def transferir(self, usuario, password, iban_destino, importe_centimos, concepto):
        """Flujo completo que usa la web: preparar, firmar y ejecutar."""
        if len(concepto.strip()) > LONGITUD_MAXIMA_CONCEPTO:
            raise ErrorBanco(f"El concepto no puede superar {LONGITUD_MAXIMA_CONCEPTO} caracteres")
        orden = self.preparar_orden(usuario, iban_destino, importe_centimos, concepto)
        firma = self.firmar_orden(usuario, password, orden)
        return self.ejecutar_orden(orden, firma, self.certificado_de(usuario))

    # =======================================================================
    # PUNTO 4 · Justificantes (firmados por el banco)
    # =======================================================================

    def _crear_justificante(self, orden, firma_cliente, certificado_cliente, fecha_ejecucion):
        """
        El justificante incluye la orden firmada por el cliente (prueba de que
        él la dio: no repudio) y la fecha de ejecución. El banco lo firma todo,
        lo que actúa como sello de tiempo: el banco certifica CUÁNDO se ejecutó.
        """
        contenido = {
            "documento": "Justificante de transferencia - BancoSeguro",
            "orden": orden,
            "firma_cliente": firma_cliente,
            "certificado_cliente": certificado_cliente,
            "fecha_ejecucion": fecha_ejecucion,
        }
        justificante = {
            "contenido": contenido,
            "firma_banco": firmas.firmar(self._clave_firma, comun.json_canonico(contenido)),
            "certificado_banco": certificados.certificado_a_pem(self.certificado_firma),
        }
        # Se guarda cifrado (contiene importes y conceptos)
        justificantes = self.almacen.leer("justificantes.json", {})
        justificantes[orden["id_orden"]] = cifrado.cifrar_json(
            self._clave_datos, justificante, ("justificante:" + orden["id_orden"]).encode()
        )
        self.almacen.guardar("justificantes.json", justificantes)
        self.registro.anotar("P4-FIRMA", f"Justificante {orden['id_orden'][:8]}… firmado por el banco con "
                                      "ECDSA P-256 + SHA-256 y guardado cifrado con AES-256-GCM")
        return justificante

    def obtener_justificante(self, usuario, id_orden):
        """Devuelve un justificante solo si el usuario es el ordenante o el beneficiario."""
        justificantes = self.almacen.leer("justificantes.json", {})
        if id_orden not in justificantes:
            raise ErrorBanco("Justificante no encontrado")
        try:
            justificante = cifrado.descifrar_json(self._clave_datos, justificantes[id_orden],
                                                 ("justificante:" + id_orden).encode())
        except comun.ErrorCriptografico as error:
            raise ErrorIntegridad("El justificante guardado ha sido manipulado") from error
        orden = justificante["contenido"]["orden"]
        iban_usuario = self.almacen.leer("usuarios.json", {})[usuario]["iban"]
        if iban_usuario not in (orden["iban_origen"], orden["iban_destino"]):
            raise ErrorBanco("Justificante no encontrado")
        return justificante

    def verificar_justificante(self, justificante):
        """
        Cualquiera puede comprobar un justificante. Devuelve una lista de
        comprobaciones (texto, correcta) y si TODAS son correctas.
        """
        resultados = []

        def comprobar(texto, funcion):
            try:
                funcion()
                resultados.append((texto, True, "correcto"))
            except (comun.ErrorCriptografico, KeyError, TypeError, AttributeError, ValueError) as error:
                resultados.append((texto, False, str(error) or "formato no válido"))

        def cert_banco():
            cert = certificados.pem_a_certificado(justificante["certificado_banco"])
            certificados.verificar_certificado(cert, self.certificado_ca, NOMBRE_FIRMA_BANCO)

        def firma_banco():
            cert = certificados.pem_a_certificado(justificante["certificado_banco"])
            if not firmas.verificar_firma(cert.public_key(), comun.json_canonico(justificante["contenido"]),
                                          justificante["firma_banco"]):
                raise comun.ErrorCriptografico("la firma del banco no corresponde al contenido (justificante alterado)")

        def cert_cliente():
            contenido = justificante["contenido"]
            cert = certificados.pem_a_certificado(contenido["certificado_cliente"])
            certificados.verificar_certificado(cert, self.certificado_ca, contenido["orden"]["ordenante"])

        def firma_cliente():
            contenido = justificante["contenido"]
            cert = certificados.pem_a_certificado(contenido["certificado_cliente"])
            if not firmas.verificar_firma(cert.public_key(), comun.json_canonico(contenido["orden"]),
                                          contenido["firma_cliente"]):
                raise comun.ErrorCriptografico("la firma del cliente no corresponde a la orden")

        comprobar("Certificado del banco emitido por la CA de BancoSeguro", cert_banco)
        comprobar("Firma ECDSA del banco sobre el justificante", firma_banco)
        comprobar("Certificado del cliente emitido por la CA de BancoSeguro", cert_cliente)
        comprobar("Firma ECDSA del cliente sobre la orden", firma_cliente)

        valido = all(correcta for _, correcta, _ in resultados)
        self.registro.anotar("P4-FIRMA", "Verificación de justificante: " + ("VÁLIDO" if valido else "NO VÁLIDO"))
        return resultados, valido
