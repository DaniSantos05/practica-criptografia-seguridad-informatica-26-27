# BancoSeguro

Práctica final de **Criptografía y Seguridad Informática** (UC3M, curso 26/27).

BancoSeguro es una banca online **ficticia** hecha con Python y Flask. Los clientes abren una cuenta,
consultan su saldo y movimientos, hacen transferencias firmadas digitalmente y descargan justificantes
firmados por el banco que cualquiera puede verificar.

Lo importante del proyecto es la **criptografía que pide el enunciado**, organizada así:

| Punto del enunciado | Qué usamos | Código | Tests |
|---|---|---|---|
| 1. Registro y autenticación | **Argon2id** + sal de 128 bits, contraseñas robustas, bloqueo tras 5 fallos | [`punto1_autenticacion.py`](banco/cripto/punto1_autenticacion.py) | [`test_punto1_autenticacion.py`](tests/test_punto1_autenticacion.py) |
| 2. Cifrado autenticado | **AES-256-GCM**, nonce aleatorio de 96 bits, AAD | [`punto2_cifrado.py`](banco/cripto/punto2_cifrado.py) | [`test_punto2_cifrado.py`](tests/test_punto2_cifrado.py) |
| 3. Autenticación de mensajes | **HMAC-SHA256** encadenado (libro de movimientos) | [`punto3_integridad.py`](banco/cripto/punto3_integridad.py) | [`test_punto3_integridad.py`](tests/test_punto3_integridad.py) |
| 4. Firma digital | **ECDSA P-256 + SHA-256** (firman el cliente y el banco) | [`punto4_firma.py`](banco/cripto/punto4_firma.py) | [`test_punto4_firma.py`](tests/test_punto4_firma.py) |
| 5. Generación y almacenamiento de claves | **Argon2id + HKDF**, claves privadas cifradas, **certificados X.509** | [`punto5_claves.py`](banco/cripto/punto5_claves.py), [`punto5_certificados.py`](banco/cripto/punto5_certificados.py) | [`test_punto5_claves.py`](tests/test_punto5_claves.py) |
| Repetición de mensajes | Id único + fecha dentro de lo firmado | `banco/banco.py` (`ejecutar_orden`) | [`test_repeticion.py`](tests/test_repeticion.py) |

📄 **[`DISENO.md`](DISENO.md)**: cómo se cumple cada punto del enunciado (qué, por qué, dónde y cómo se demuestra).
❓ **[`PREGUNTAS_DEFENSA.md`](PREGUNTAS_DEFENSA.md)**: preguntas probables de la defensa con respuesta corta.

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

Hay 94 pruebas, positivas y negativas, **organizadas por punto del enunciado** (`test_punto1_...` a
`test_punto5_...`), más la repetición de mensajes, la interfaz web y los 15 ataques del laboratorio. Cada
prueba crea su propio banco en una carpeta temporal, así que no dependen unas de otras ni tocan los datos reales.

Para ver solo las de un punto: `python -m pytest -v tests/test_punto2_cifrado.py`

## Guion para la demostración

1. **Registro**: crear dos clientes (por ejemplo `ana` y `luis`). Probar una contraseña corta o común → rechazada.
2. **Transferencia**: entrar como `ana` y enviar dinero a `luis`. Probar con contraseña incorrecta → no se puede firmar.
3. **Justificante**: descargarlo desde "Mi cuenta" y comprobarlo en "Verificar justificante". Cambiar el
   importe en el fichero y verificarlo otra vez → no válido.
4. **Manipular los datos**: abrir `datos/cuentas.json`, cambiar un carácter del campo `cifrado` y recargar
   "Mi cuenta" → el banco detecta la manipulación y no muestra los datos.
5. **Laboratorio de ataques**: lanzar los 15 ataques (agrupados por punto del enunciado) y comprobar que todos se rechazan.
6. **Registro de seguridad**: ver cada operación con su algoritmo y longitud de clave, etiquetada con su punto (P1 a P5).

## Estructura

```
├── banco/
│   ├── cripto/                  TODA la criptografía, un archivo por punto del enunciado
│   │   ├── punto1_autenticacion.py   Argon2id y política de contraseñas
│   │   ├── punto2_cifrado.py         AES-256-GCM
│   │   ├── punto3_integridad.py      HMAC-SHA256
│   │   ├── punto4_firma.py           ECDSA P-256
│   │   ├── punto5_claves.py          Derivación (Argon2id, HKDF) y protección de claves privadas
│   │   ├── punto5_certificados.py    Certificados X.509 y verificación (PKI del banco)
│   │   └── comun.py                  Aleatoriedad, JSON canónico y errores
│   ├── banco.py                 Lógica del banco (usa banco/cripto/)
│   ├── laboratorio.py           15 ataques contra un banco temporal
│   ├── almacen.py               Ficheros JSON
│   └── registro.py              Registro (log) de seguridad
├── app.py                       Interfaz web (Flask)
├── templates/, static/          Páginas HTML y estilo
├── tests/                       Pruebas, una por punto del enunciado
├── DISENO.md                    Cómo se cumple cada punto del enunciado
└── PREGUNTAS_DEFENSA.md         Preparación de la defensa
```

El repositorio no contiene claves, contraseñas ni datos personales: todo se genera al ejecutar.
