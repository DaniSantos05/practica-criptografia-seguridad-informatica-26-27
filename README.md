# BancoSeguro

Práctica final de **Criptografía y Seguridad Informática** (UC3M, curso 26/27).

BancoSeguro es una banca online **ficticia** hecha con Python y Flask. Los clientes abren una cuenta,
consultan su saldo y movimientos, hacen transferencias firmadas digitalmente y descargan justificantes
firmados por el banco que cualquiera puede verificar.

| Requisito del enunciado | Cómo se cumple |
|---|---|
| Registro y autenticación | Contraseñas guardadas con **Argon2id** + sal; bloqueo tras 5 intentos fallidos |
| Cifrado (autenticado) | Saldos, movimientos y justificantes cifrados con **AES-256-GCM** |
| Autenticación de mensajes | **HMAC-SHA256** encadenado en el libro de movimientos |
| Firma digital | Los clientes firman cada orden con **ECDSA P-256**; el banco firma los justificantes |
| Gestión de claves | Clave maestra derivada de una frase (no se guarda) + **HKDF**; claves privadas cifradas; **certificados X.509** emitidos por la CA del banco |

Las decisiones de diseño y su justificación están en [`DISENO.md`](DISENO.md).

## Requisitos

- Python 3.10 o posterior.
- Dependencias con versión fijada en [`requirements.txt`](requirements.txt):
  `cryptography==46.0.3`, `Flask==3.1.2` y `pytest==8.4.2` (solo para los tests).

## Instalación (desde un entorno limpio)

```bash
git clone https://github.com/DaniSantos05/practica-criptografia-seguridad-informatica-26-27.git
cd practica-criptografia-seguridad-informatica-26-27

python3 -m venv .venv
source .venv/bin/activate          # En Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Ejecución

```bash
python app.py
```

1. La primera vez pide elegir la **frase maestra** del banco (mínimo 12 caracteres). De ella se derivan
   todas las claves del banco y **no se guarda en ningún sitio**: hay que recordarla.
2. Las siguientes veces pide esa misma frase. Si es incorrecta, el banco no arranca.
3. Abrir <http://127.0.0.1:5000> en el navegador.

Los datos se guardan en la carpeta `datos/` (se crea sola y está excluida de Git). Para empezar de cero,
basta con borrarla.

## Pruebas

```bash
python -m pytest -v
```

Hay 76 pruebas, positivas y negativas: primitivas criptográficas, funcionamiento del banco, interfaz web
y los 13 ataques del laboratorio. Cada prueba crea su propio banco en una carpeta temporal, así que no
dependen unas de otras ni tocan los datos reales.

## Guion para la demostración

1. **Registro**: crear dos clientes (por ejemplo `ana` y `luis`). Probar una contraseña corta o común → rechazada.
2. **Transferencia**: entrar como `ana` y enviar dinero a `luis`. Probar con contraseña incorrecta → no se puede firmar.
3. **Justificante**: descargarlo desde "Mi cuenta" y comprobarlo en "Verificar justificante". Cambiar el
   importe en el fichero y verificarlo otra vez → no válido.
4. **Manipular los datos**: abrir `datos/cuentas.json`, cambiar un carácter del campo `cifrado` y recargar
   "Mi cuenta" → el banco detecta la manipulación y no muestra los datos.
5. **Laboratorio de ataques**: lanzar los 13 ataques y comprobar que todos se rechazan.
6. **Registro de seguridad**: ver cada operación con su algoritmo y longitud de clave.

## Estructura

```
├── app.py                  Interfaz web (Flask): páginas y formularios
├── banco/
│   ├── cripto.py           TODA la criptografía (Argon2id, AES-GCM, HKDF, HMAC, ECDSA, X.509)
│   ├── banco.py            Lógica del banco (registro, login, cuentas, transferencias, justificantes)
│   ├── laboratorio.py      Ataques que se lanzan contra un banco temporal
│   ├── almacen.py          Lectura y escritura de los ficheros JSON
│   ├── registro.py         Registro (log) de seguridad
│   └── contrasenas_comunes.txt
├── templates/              Páginas HTML
├── static/estilo.css
└── tests/                  Pruebas automáticas (pytest)
```

El repositorio no contiene claves, contraseñas ni datos personales: todo se genera al ejecutar.
