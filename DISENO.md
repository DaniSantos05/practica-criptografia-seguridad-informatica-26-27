# Diseño de BancoSeguro

Este documento explica **qué** hace la aplicación, **cómo** está construida y **por qué** se ha elegido
cada algoritmo, con referencia a los temas y prácticas de la asignatura. Es la base de la memoria y de
la defensa.

## 1. Propósito

Una banca online ficticia. Un cliente puede:

1. Abrir una cuenta (recibe 1.000 € de saldo de bienvenida).
2. Iniciar sesión y consultar su saldo y movimientos.
3. Hacer transferencias a otros clientes, **firmándolas digitalmente**.
4. Descargar el **justificante** de cada transferencia, firmado por el banco.
5. Verificar cualquier justificante (incluso sin tener cuenta).

Además, la web incluye un **laboratorio de ataques** y un **registro de seguridad** para la demostración.

La temática se eligió porque cada medida de seguridad responde a un problema que todo el mundo entiende:
que no te cambien el importe de una transferencia, que no te cobren dos veces o que nadie pueda hacer
pagos en tu nombre. Los propios ejemplos de las prácticas de clase son bancarios (`"Transfer 100 euros"`).

## 2. Estructura interna

| Capa | Fichero | Responsabilidad |
|---|---|---|
| Interfaz | `app.py`, `templates/` | Páginas, formularios, sesión y token CSRF. No hace criptografía. |
| Lógica | `banco/banco.py` | Reglas del banco. Llama a `cripto.py` y anota cada paso en el registro. |
| Criptografía | `banco/cripto.py` | **Todas** las operaciones criptográficas, en funciones pequeñas y comentadas. |
| Datos | `banco/almacen.py` | Ficheros JSON en `datos/` (escritura atómica y permisos `600`). |
| Registro | `banco/registro.py` | Log de seguridad sin secretos. |
| Ataques | `banco/laboratorio.py` | Ataques reales contra un banco temporal. |

### Ficheros de datos (`datos/`)

| Fichero | Contenido | Protección |
|---|---|---|
| `config_banco.json` | Sal de la frase maestra, certificados y claves privadas del banco | Claves privadas cifradas con AES-256-GCM |
| `usuarios.json` | Resumen Argon2id de la contraseña, clave de firma del cliente y su certificado | Contraseña: solo el resumen. Clave privada cifrada con una clave derivada de la contraseña del cliente |
| `cuentas.json` | Saldo, nº de movimientos y HMAC del último movimiento | AES-256-GCM, AAD = IBAN |
| `movimientos.json` | Movimientos de cada cuenta | AES-256-GCM (AAD = IBAN + id) + HMAC-SHA256 encadenado |
| `justificantes.json` | Justificantes firmados | Firma ECDSA del banco + AES-256-GCM |
| `registro_seguridad.log` | Log de operaciones | Sin secretos |

## 3. Decisiones criptográficas

### 3.1 Autenticación de usuarios (tema 9, práctica 1)

- **Factor**: algo que sabemos (contraseña), que es el mínimo obligatorio.
- **Almacenamiento**: solo se guarda el resumen **Argon2id** (`t=3` iteraciones, `m=64 MiB`, `p=4`,
  salida de 256 bits) con una **sal aleatoria de 128 bits** por usuario.
  - En la práctica 1 se ve que SHA-256 sin sal es inseguro: la misma contraseña da el mismo hash y un
    ataque de diccionario lo rompe enseguida. La sal impide las tablas precalculadas, y Argon2id es
    lento y consume memoria, lo que hace caro cada intento, también con GPU.
  - Argon2id es la función recomendada actualmente (ganadora de la Password Hashing Competition). Está
    en la propia librería `cryptography`, así que no hace falta otra dependencia.
- **Política de contraseñas** (tema 9, "criterios de calidad"): mínimo 12 caracteres, no puede contener
  el usuario y se rechazan las que aparecen en una lista de contraseñas comunes, que se usan en ataques
  de diccionario.
- **Bloqueo** tras 5 intentos fallidos durante 5 minutos (tema 9, "bloqueo ante sospecha de uso
  fraudulento"). Esto frena la fuerza bruta en línea.
- **Mensaje genérico** ("Usuario o contraseña incorrectos") y cálculo de Argon2id también cuando el
  usuario no existe: así no se revela qué usuarios existen, ni por el texto ni por el tiempo de respuesta.
- **Sesión web**: cookie firmada por Flask (HMAC) con `HttpOnly` y `SameSite=Lax`, caducidad de 15
  minutos y token **CSRF** en todos los formularios.

### 3.2 Cifrado (temas 3 y 4, práctica 2)

- **Algoritmo**: **AES-256-GCM**, que es cifrado autenticado (AEAD). Da a la vez confidencialidad
  e integridad, como pide el enunciado ("siempre que sea posible, cifrado autenticado").
  - No se usa ECB porque bloques iguales dan cifrados iguales y deja ver patrones (práctica 2,
    ejercicio 2). Tampoco CBC sin MAC, porque no da integridad y necesita relleno (práctica 2,
    ejercicio 1).
  - AES-256 es el estándar del NIST, elegido entre otros usos "para transferencia de fondos bancarios" (tema 3).
- **Nonce**: 96 bits aleatorios (`os.urandom`), **nuevo en cada cifrado**. GCM funciona en modo contador
  (como un cifrado en flujo): repetir nonce con la misma clave permitiría obtener `M1 ⊕ M2` (tema 2) y
  falsificar tags. Con nonces aleatorios de 96 bits la probabilidad de repetición es despreciable para
  el volumen de esta aplicación.
- **Datos asociados (AAD)**: el IBAN, y en los movimientos también su identificador. El AAD no se cifra
  pero sí se autentica: si alguien copia el saldo cifrado de una cuenta en otra, el descifrado falla.
- **Qué se cifra**: el estado de cada cuenta (saldo), los movimientos (importe, concepto, contraparte...),
  los justificantes guardados y las claves privadas.

### 3.3 Integridad y autenticación de mensajes (tema 4)

- Cada registro cifrado ya está protegido por el tag de GCM (128 bits).
- Además, cada movimiento lleva un **HMAC-SHA256** (clave de 256 bits) calculado sobre el movimiento
  **ya cifrado** (Encrypt-then-MAC), el IBAN y **el HMAC del movimiento anterior**. Así los movimientos
  forman una cadena:
  - Si se modifica, mueve o reordena un movimiento, su HMAC no coincide.
  - Si se borra un movimiento, el número de movimientos y el "último HMAC" (guardados cifrados en el
    estado de la cuenta) no coinciden.
  - Se comprueba también que el saldo es igual a la suma de los movimientos.
  - Esto es lo que dice el tema 4: un MAC que incluye un número de secuencia evita la repetición y la
    reordenación. Es una idea parecida a los árboles de Merkle (tema 7).
- La clave del HMAC es **distinta** de la de cifrado. Las dos se derivan con HKDF de la clave maestra:
  "la utilización de claves independientes para cifrado y MAC es el modo sólido" (tema 4).
- **Si una verificación falla**, se lanza `ErrorIntegridad`, la web muestra una página de aviso, no se
  muestran ni se usan los datos y el incidente se anota en el registro.

### 3.4 Firma digital (temas 6 y 7, práctica 3)

- **Algoritmo**: **ECDSA con la curva P-256 y SHA-256** (el ejemplo que da el enunciado). P-256 ofrece
  unos 128 bits de seguridad, equivalente a RSA-3072 y a AES-128 (tabla del tema 6), con claves y
  firmas mucho más cortas.
- **Qué se firma**:
  1. **El cliente firma cada orden de transferencia** (id aleatorio, ordenante, cuentas, importe,
     concepto y fecha). Esto da autenticación del origen, integridad y **no repudio**: el cliente no
     puede negar después que la hizo (tema 7).
  2. **El banco firma cada justificante**, que incluye la orden firmada por el cliente y la fecha de
     ejecución. Esa fecha firmada por el banco funciona como **sello de tiempo** (tema 7: "sello de
     tiempo ≠ marca de tiempo").
- Se sigue el paradigma **"resume y firma"**: SHA-256 de la orden y firma del resumen. La orden se
  serializa en **JSON canónico** (claves ordenadas y sin espacios), para que el mismo contenido dé
  siempre los mismos bytes.
- ECDSA es un esquema **aleatorio con apéndice** (tema 7). El valor secreto de cada firma lo genera la
  librería con un generador seguro; repetirlo revelaría la clave privada.
- No se usa RSA con PKCS#1 v1.5 (práctica 3, pregunta d).
- **Verificación**: el banco verifica antes de ejecutar nada. Si la firma es inválida, la orden se
  rechaza (`OrdenRechazada`) y se anota en el registro.
- **Firma ≠ cifrado**: la firma no da confidencialidad (tema 7). Por eso los datos se cifran aparte con
  AES-GCM.

### 3.5 Certificados y PKI (tema 8, práctica 4)

- El banco tiene su propia **autoridad de certificación (CA)** con un certificado X.509 autofirmado
  (`BasicConstraints ca=True`, `keyUsage = keyCertSign, cRLSign`, 5 años).
- Al registrarse, cada cliente recibe un **certificado X.509** que vincula su nombre con su clave
  pública (`ca=False`, `keyUsage = digitalSignature, contentCommitment` (no repudio), **1 año**).
  La Ley 6/2020 limita a menos de 5 años la vigencia de los certificados cualificados (tema 10).
- La clave con la que el banco firma justificantes también tiene su propio certificado emitido por la
  CA. Es **una clave distinta** de la de la CA: cada clave tiene un único uso.
- **Verificación de un certificado** (`cripto.verificar_certificado`). Como se ve en la práctica 4,
  *una firma válida no basta*; se comprueba:
  1. que lo ha firmado la CA del banco;
  2. que está dentro de su periodo de validez;
  3. que el nombre del certificado es el del ordenante (caso `attacker.com` de la práctica 4);
  4. que no es un certificado de CA y que su `keyUsage` permite firmar.

### 3.6 Generación y almacenamiento de claves

| Clave | Cómo se genera | Dónde se guarda |
|---|---|---|
| Clave maestra del banco (256 bits) | Argon2id a partir de la **frase maestra** que se escribe al arrancar, con sal aleatoria | **No se guarda**: se recalcula en cada arranque (opción "derivar de una contraseña" del enunciado) |
| Clave de cifrado de datos (256 bits) | HKDF-SHA256 desde la clave maestra (`info="cifrado de datos"`) | Solo en memoria |
| Clave HMAC (256 bits) | HKDF-SHA256 desde la clave maestra (`info="hmac de movimientos"`) | Solo en memoria |
| Claves privadas de la CA y de firma del banco (ECDSA P-256) | `ec.generate_private_key` | PKCS#8 cifrado con AES-256-GCM (clave de datos) |
| Clave privada de cada cliente (ECDSA P-256) | `ec.generate_private_key` al registrarse | PKCS#8 cifrado con AES-256-GCM con una clave **derivada de la contraseña del cliente** (Argon2id, sal propia) |
| Sales y nonces | `os.urandom` (generador seguro del sistema) | Junto a los datos (no son secretos) |
| Clave de la cookie de sesión | `secrets.token_bytes(32)` en cada arranque | Solo en memoria |

- Se comprueba que la frase maestra es correcta descifrando un texto conocido: si el tag de GCM falla,
  el banco no arranca.
- Para firmar una transferencia el cliente debe escribir su contraseña: es lo que descifra su clave
  privada en ese momento. Así **ni el banco puede firmar en nombre del cliente**. Esto se corresponde
  con el requisito de "control exclusivo" de la firma electrónica avanzada (eIDAS, tema 10) y con que
  el prestador "no almacene datos de creación de firma" (Ley 6/2020).
- Ninguna clave, IV o nonce es constante ni está en el código (errores de la práctica 2). El repositorio
  no contiene secretos: todo se genera al ejecutar.

### 3.7 Protección contra la repetición (replay) (práctica 3, pregunta 2)

- Cada orden lleva un **identificador aleatorio de 128 bits** y la **fecha**, ambos **dentro de lo firmado**.
- El banco rechaza una orden si su identificador ya aparece en los movimientos (que están protegidos
  con HMAC, así que no se puede borrar el rastro) o si tiene más de **5 minutos**.

## 4. Ataques y cómo se mitigan

Todos se pueden lanzar desde la página **Laboratorio de ataques** y están en `tests/test_laboratorio.py`.

| # | Ataque | Amenaza (tema 1) | Mitigación |
|---|---|---|---|
| 1 | Cambiar el importe de una orden firmada | Modificación → integridad | Firma ECDSA |
| 2 | Alterar un byte de la firma | Modificación | Verificación ECDSA |
| 3 | Repetir una orden ya ejecutada | Generación → autenticación | Id único dentro de la firma |
| 4 | Presentar una orden antigua | Generación | Fecha firmada y caducidad de 5 min |
| 5 | Eva firma en nombre de Ana con su propio certificado | Generación (suplantación) | El certificado debe ser del ordenante |
| 6 | Certificado de "ana" emitido por una CA falsa | Generación (suplantación) | Verificar que lo firmó la CA del banco |
| 7 | Firmar sin la contraseña del cliente | Generación | Clave privada cifrada con clave derivada de la contraseña |
| 8 | Cambiar un byte del saldo cifrado en el disco | Modificación | Tag AES-GCM |
| 9 | Copiar el saldo cifrado de otra cuenta | Modificación | AAD = IBAN |
| 10 | Borrar un movimiento para ocultar un cargo | Modificación | HMAC encadenado + contador cifrado |
| 11 | Copiar un movimiento de otra cuenta | Modificación | HMAC con el IBAN |
| 12 | Modificar un justificante | Modificación | Firma del banco y del cliente |
| 13 | Fuerza bruta contra una contraseña | Interceptación / suplantación | Argon2id + bloqueo tras 5 fallos |

Otros riesgos tenidos en cuenta: robo del fichero de datos (todo cifrado o como resumen Argon2id),
ataque de diccionario sin conexión (sal y Argon2id), CSRF (token por sesión) y enumeración de usuarios
(mensaje genérico y tiempo constante).

## 5. Limitaciones (mejoras para un sistema real)

- La web funciona en local con HTTP. En producción iría sobre **HTTPS (TLS 1.3)**, cuyo handshake con
  ECDHE da secreto hacia delante (tema 6).
- Las firmas de los clientes se calculan en el servidor, aunque con una clave que solo se descifra con
  la contraseña del cliente. En un sistema real se generarían en el dispositivo del cliente o en una
  tarjeta o HSM (tema 8). Eso sería necesario para una firma **cualificada** (eIDAS).
- No hay revocación de certificados (CRL u OCSP), ni CA intermedia, ni segundo factor de autenticación
  (por ejemplo el OTP síncrono/TOTP del tema 9, que exige PSD2 para pagos).
- Los algoritmos de clave pública actuales (ECDSA, RSA) serían vulnerables a un ordenador cuántico
  (algoritmo de Shor). La alternativa sería ML-DSA (tema 7).
- Los ficheros JSON y el cerrojo en memoria sirven para una demostración, no para muchos usuarios a la vez.

## 6. Dependencias

| Librería | Versión | Uso |
|---|---|---|
| `cryptography` | 46.0.3 | Toda la criptografía (la misma librería de las prácticas de clase) |
| `Flask` | 3.1.2 | Interfaz web |
| `pytest` | 8.4.2 | Pruebas |
