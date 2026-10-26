"""
Interfaz web de BancoSeguro (Flask).

Este fichero solo se ocupa de las páginas y los formularios: toda la lógica está
en banco/banco.py y toda la criptografía en banco/cripto/ (un archivo por punto del enunciado).

Ejecución:  python app.py   y abrir  http://127.0.0.1:5000
"""

import getpass
import json
import os
import secrets
import sys
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps

from flask import Flask, abort, flash, redirect, render_template, request, Response, session, url_for

from banco.cripto import comun
from banco.banco import Banco, ErrorBanco, ErrorIntegridad, FraseMaestraIncorrecta, euros
from banco.laboratorio import ejecutar_laboratorio

CARPETA_DATOS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "datos")


def importe_a_centimos(texto):
    """Convierte lo que escribe el usuario ('50', '50,5', '1.250,75') en céntimos."""
    texto = texto.strip().replace(" ", "").replace("€", "")
    if "," in texto:  # formato español: el punto separa miles y la coma los decimales
        texto = texto.replace(".", "").replace(",", ".")
    try:
        cantidad = Decimal(texto)
    except InvalidOperation:
        raise ErrorBanco("El importe no es un número válido") from None
    if not cantidad.is_finite() or cantidad <= 0 or cantidad.as_tuple().exponent < -2:
        raise ErrorBanco("El importe debe ser positivo y tener como máximo dos decimales")
    return int(cantidad * 100)


def crear_app(banco):
    app = Flask(__name__)

    # Clave con la que Flask firma (HMAC) la cookie de sesión. Es aleatoria en
    # cada arranque, así que al reiniciar el servidor todas las sesiones caducan.
    app.secret_key = secrets.token_bytes(32)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,      # JavaScript no puede leer la cookie
        SESSION_COOKIE_SAMESITE="Lax",     # la cookie no se envía desde otras webs
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
        MAX_CONTENT_LENGTH=64 * 1024,      # rechaza peticiones enormes
    )

    app.jinja_env.filters["euros"] = euros
    app.jinja_env.filters["fecha"] = lambda iso: datetime.fromisoformat(iso).astimezone().strftime("%d/%m/%Y %H:%M")

    # ---------------------------------------------------------------- CSRF
    # Cada formulario lleva un token aleatorio guardado en la sesión. Una web
    # maliciosa no lo conoce, así que no puede enviar formularios en nombre
    # del usuario (ataque CSRF).

    def token_csrf():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return session["csrf"]

    app.jinja_env.globals["token_csrf"] = token_csrf

    @app.before_request
    def comprobar_csrf():
        if request.method == "POST":
            enviado = request.form.get("csrf", "")
            if not enviado or not comun.iguales(enviado, session.get("csrf", "")):
                abort(400, "Token CSRF no válido")

    # ------------------------------------------------------- sesión y acceso

    def requiere_login(vista):
        @wraps(vista)
        def envoltura(*args, **kwargs):
            if "usuario" not in session:
                flash("Inicia sesión para continuar", "aviso")
                return redirect(url_for("login"))
            return vista(*args, **kwargs)
        return envoltura

    def abrir_sesion(usuario):
        session.clear()               # evita reutilizar una sesión anterior
        session.permanent = True
        session["usuario"] = usuario

    # --------------------------------------------------------------- páginas

    @app.get("/")
    def inicio():
        if "usuario" in session:
            return redirect(url_for("cuenta"))
        return render_template("inicio.html")

    @app.route("/registro", methods=["GET", "POST"])
    def registro():
        if request.method == "POST":
            usuario = request.form.get("usuario", "")
            password = request.form.get("password", "")
            if password != request.form.get("password2", ""):
                flash("Las contraseñas no coinciden", "error")
                return render_template("registro.html", usuario=usuario)
            try:
                banco.registrar(usuario, password)
            except ErrorBanco as error:
                flash(str(error), "error")
                return render_template("registro.html", usuario=usuario)
            abrir_sesion(usuario.strip().lower())
            flash("Cuenta creada. Te hemos regalado 1.000,00 € de saldo de bienvenida", "ok")
            return redirect(url_for("cuenta"))
        return render_template("registro.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            try:
                usuario = banco.iniciar_sesion(request.form.get("usuario", ""), request.form.get("password", ""))
            except ErrorBanco as error:
                flash(str(error), "error")
                return render_template("login.html")
            abrir_sesion(usuario)
            return redirect(url_for("cuenta"))
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        session.clear()
        flash("Sesión cerrada", "ok")
        return redirect(url_for("inicio"))

    @app.get("/cuenta")
    @requiere_login
    def cuenta():
        try:
            datos = banco.consultar_cuenta(session["usuario"])
        except ErrorIntegridad as error:
            # Los datos han sido manipulados: no se muestran
            return render_template("integridad.html", motivo=str(error)), 409
        return render_template("cuenta.html", cuenta=datos)

    @app.route("/transferir", methods=["GET", "POST"])
    @requiere_login
    def transferir():
        usuario = session["usuario"]
        destinatarios = banco.listar_destinatarios(usuario)
        if request.method == "POST":
            try:
                justificante = banco.transferir(
                    usuario,
                    request.form.get("password", ""),
                    request.form.get("iban_destino", ""),
                    importe_a_centimos(request.form.get("importe", "")),
                    request.form.get("concepto", ""),
                )
            except ErrorBanco as error:
                flash(str(error), "error")
                return render_template("transferir.html", destinatarios=destinatarios, formulario=request.form)
            orden = justificante["contenido"]["orden"]
            flash(f"Transferencia de {euros(orden['importe_centimos'])} realizada y firmada correctamente", "ok")
            return redirect(url_for("cuenta"))
        return render_template("transferir.html", destinatarios=destinatarios, formulario={})

    @app.get("/justificante/<id_orden>")
    @requiere_login
    def descargar_justificante(id_orden):
        try:
            justificante = banco.obtener_justificante(session["usuario"], id_orden)
        except ErrorBanco:
            abort(404)
        return Response(
            json.dumps(justificante, indent=2, ensure_ascii=False),
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename=justificante_{id_orden[:8]}.json"},
        )

    @app.route("/verificar", methods=["GET", "POST"])
    def verificar():
        """Verificación pública de justificantes (no hace falta tener cuenta)."""
        resultado = None
        texto = ""
        if request.method == "POST":
            fichero = request.files.get("fichero")
            texto = fichero.read().decode("utf-8", "replace") if fichero and fichero.filename else request.form.get("texto", "")
            try:
                justificante = json.loads(texto)
                comprobaciones, valido = banco.verificar_justificante(justificante)
                resultado = {"comprobaciones": comprobaciones, "valido": valido,
                             "orden": justificante.get("contenido", {}).get("orden", {})}
            except (json.JSONDecodeError, AttributeError):
                flash("El texto no es un justificante JSON válido", "error")
        return render_template("verificar.html", resultado=resultado, texto=texto)

    @app.route("/laboratorio", methods=["GET", "POST"])
    def laboratorio():
        resultados = ejecutar_laboratorio() if request.method == "POST" else None
        return render_template("laboratorio.html", resultados=resultados)

    @app.get("/seguridad")
    def registro_seguridad():
        return render_template("seguridad.html", lineas=banco.registro.ultimas())

    @app.errorhandler(400)
    def peticion_incorrecta(error):
        return render_template("error.html", mensaje="Petición no válida (token de seguridad incorrecto o caducado). "
                                                     "Vuelve a cargar la página."), 400

    @app.errorhandler(404)
    def no_encontrado(error):
        return render_template("error.html", mensaje="Página no encontrada"), 404

    return app


def pedir_frase_maestra():
    """
    La frase maestra protege todas las claves del banco. No se guarda en el
    código ni en ningún fichero: se escribe al arrancar (o se pasa en la
    variable de entorno BANCO_FRASE_MAESTRA, útil para pruebas).
    """
    frase = os.environ.get("BANCO_FRASE_MAESTRA")
    if frase:
        return frase
    primera_vez = not os.path.exists(os.path.join(CARPETA_DATOS, "config_banco.json"))
    if primera_vez:
        print("Primera ejecución: elige la frase maestra del banco (mínimo 12 caracteres).")
        print("¡Apúntala! Sin ella no se pueden descifrar los datos.")
    frase = getpass.getpass("Frase maestra del banco: ")
    if primera_vez and frase != getpass.getpass("Repite la frase maestra: "):
        sys.exit("Las frases no coinciden")
    return frase


def main():
    try:
        banco = Banco(CARPETA_DATOS, pedir_frase_maestra())
    except FraseMaestraIncorrecta:
        sys.exit("Frase maestra incorrecta: no se pueden descifrar las claves del banco.")
    except ErrorBanco as error:
        sys.exit(str(error))
    print("\nBancoSeguro disponible en  http://127.0.0.1:5000  (Ctrl+C para parar)\n")
    # Solo escucha en la propia máquina (127.0.0.1) y sin modo debug
    crear_app(banco).run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
