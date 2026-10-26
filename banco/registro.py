"""
Registro de seguridad (log).

Cada operación criptográfica deja una línea con el algoritmo, la longitud de
clave y el resultado, como pide el enunciado. NUNCA se escriben claves,
contraseñas ni otros secretos.

Las líneas se muestran en la terminal, se guardan en un fichero y se pueden ver
en la web (página "Registro de seguridad").
"""

from datetime import datetime


class RegistroSeguridad:
    def __init__(self, ruta_fichero, mostrar_en_terminal=True):
        self.ruta_fichero = ruta_fichero
        self.mostrar_en_terminal = mostrar_en_terminal

    def anotar(self, categoria, mensaje):
        linea = f"{datetime.now():%Y-%m-%d %H:%M:%S} [{categoria}] {mensaje}"
        if self.mostrar_en_terminal:
            print(linea)
        with open(self.ruta_fichero, "a", encoding="utf-8") as fichero:
            fichero.write(linea + "\n")

    def ultimas(self, cantidad=150):
        """Últimas líneas del registro, de la más reciente a la más antigua."""
        try:
            with open(self.ruta_fichero, "r", encoding="utf-8") as fichero:
                lineas = fichero.read().splitlines()
        except FileNotFoundError:
            return []
        return list(reversed(lineas[-cantidad:]))
