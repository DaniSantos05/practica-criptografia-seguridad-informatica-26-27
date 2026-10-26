"""
Lectura y escritura de los ficheros de datos (JSON).

Se usan ficheros JSON en lugar de una base de datos para que se puedan abrir y
leer a simple vista: así en la demostración se ve que los datos sensibles están
cifrados, y se puede "atacar" el fichero editándolo a mano.
"""

import copy
import json
import os
from pathlib import Path


class Almacen:
    def __init__(self, carpeta):
        self.carpeta = Path(carpeta)
        # Permisos restrictivos: solo el propietario puede entrar en la carpeta
        self.carpeta.mkdir(mode=0o700, parents=True, exist_ok=True)

    def ruta(self, nombre):
        return self.carpeta / nombre

    def leer(self, nombre, por_defecto):
        """Devuelve el contenido del fichero, o 'por_defecto' si todavía no existe."""
        ruta = self.ruta(nombre)
        if not ruta.exists():
            return copy.deepcopy(por_defecto)
        with ruta.open("r", encoding="utf-8") as fichero:
            return json.load(fichero)

    def guardar(self, nombre, datos):
        """
        Guarda de forma atómica: se escribe en un fichero temporal y después se
        renombra. Si el programa se interrumpe a mitad, el fichero original no
        queda a medio escribir.
        """
        ruta = self.ruta(nombre)
        temporal = ruta.with_suffix(".tmp")
        with temporal.open("w", encoding="utf-8") as fichero:
            json.dump(datos, fichero, indent=2, ensure_ascii=False)
        os.chmod(temporal, 0o600)  # solo el propietario puede leerlo y escribirlo
        os.replace(temporal, ruta)
