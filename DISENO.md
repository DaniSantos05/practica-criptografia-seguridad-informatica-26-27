# BancoSeguro: cómo se cumple cada punto del enunciado

Este documento sigue **el orden del enunciado de la práctica**. Para cada punto indica:

- **Enunciado**: lo que se pide (cita literal).
- **Qué hacemos**: la decisión, con algoritmos y parámetros.
- **Por qué**: la justificación, con referencia a los temas (T1–T10) y prácticas (P1–P4) de la asignatura.
- **Dónde está**: archivo y función del código.
- **Cómo se demuestra**: tests, ataques del laboratorio y qué enseñar en la demo.

La aplicación (una banca online ficticia) es solo el contexto. Lo importante es la criptografía, que está
**toda** en la carpeta `banco/cripto/`, con **un archivo por punto del enunciado**.

---

## 0. Mapa rápido (rúbrica → dónde está)

| Criterio de evaluación | Punto | Código | Tests | Laboratorio |
|---|---|---|---|---|
| Autenticación de usuarios (1,5) | 1 | `banco/cripto/punto1_autenticacion.py` | `tests/test_punto1_autenticacion.py` | P1 (2 ataques) |
| Cifrado y descifrado (1,5) | 2 | `banco/cripto/punto2_cifrado.py` | `tests/test_punto2_cifrado.py` | P2 (2 ataques) |
| Integridad/autenticación de mensajes (1,0) | 3 | `banco/cripto/punto3_integridad.py` | `tests/test_punto3_integridad.py` | P3 (2 ataques) |
| Firma digital (1,5) | 4 | `banco/cripto/punto4_firma.py` | `tests/test_punto4_firma.py` | P4 (3 ataques) |
| Claves / IVs / nonces (2,0) | 5 | `banco/cripto/punto5_claves.py`, `punto5_certificados.py` | `tests/test_punto5_claves.py` | P5 (4 ataques) |
| Calidad del software (2,5) | — | Capas separadas (sección 7) | `tests/test_web.py`, `tests/test_repeticion.py`, `tests/test_laboratorio.py` | 15 ataques en total |

En el **registro de seguridad** (terminal, fichero `datos/registro_seguridad.log` y página web) cada línea
lleva la etiqueta de su punto: `P1-AUTENTICACION`, `P2-CIFRADO`, `P3-MAC`, `P4-FIRMA`, `P5-CLAVES` y `P5-PKI`.

### Estructura del código

| Capa | Archivo | Qué hace |
|---|---|---|
| Criptografía | `banco/cripto/` | **Todas** las operaciones criptográficas, en funciones cortas y comentadas |
| Lógica | `banco/banco.py` | Reglas del banco: llama a `banco/cripto/` y anota cada paso en el registro |
| Interfaz | `app.py`, `templates/` | Páginas web y formularios. No hace criptografía |
| Datos | `banco/almacen.py` | Ficheros JSON en `datos/` (escritura atómica, permisos `600`) |
| Registro | `banco/registro.py` | Log de seguridad sin secretos |
| Ataques | `banco/laboratorio.py` | 15 ataques reales contra un banco temporal |

### Propósito de la aplicación

Una banca online ficticia. Los clientes abren una cuenta (con 1.000 € de bienvenida), inician sesión,
consultan su saldo y movimientos, hacen **transferencias firmadas** y descargan **justificantes firmados
por el banco** que cualquiera puede verificar. Se eligió esta temática porque cada medida de seguridad
responde a un problema evidente: que no te cambien el importe, que no te cobren dos veces o que nadie
pague en tu nombre. Los propios ejemplos de las prácticas de clase son bancarios (`"Transfer 100 euros"`).

---

## 1. Registro y autenticación de usuarios

> **Enunciado:** *"Basado en algo que sabemos: contraseñas; se deben almacenar convenientemente y a ser
> posible que sean robustas. Esta será la opción mínima obligatoria."*

### Qué hacemos
- **Factor**: algo que sabemos (contraseña).
- **Almacenamiento**: la contraseña **nunca** se guarda. Se guarda su resumen **Argon2id**:
  - sal aleatoria de **128 bits** distinta para cada usuario (`os.urandom`);
  - `t = 3` iteraciones, `m = 64 MiB` de memoria y `p = 4` hilos;
  - salida de **256 bits**.
- **Verificación** con `Argon2id.verify()`, que compara en tiempo constante.
- **Contraseñas robustas**: mínimo 12 caracteres, que no contengan el nombre de usuario y que no estén
  en una lista de contraseñas comunes (diccionario de ataque).
- **Bloqueo** de 5 minutos tras **5 intentos fallidos**.
- **Mensaje genérico** ("Usuario o contraseña incorrectos") y cálculo de Argon2id **también** cuando el
  usuario no existe: no se revela qué usuarios existen, ni por el texto ni por el tiempo de respuesta.
- **Sesión web**: cookie firmada por Flask, `HttpOnly`, `SameSite=Lax`, caduca a los 15 minutos;
  **token CSRF** en todos los formularios.

### Por qué
- **P1** muestra que SHA-256 sin sal es inseguro: la misma contraseña da el mismo hash y un ataque de
  diccionario la encuentra enseguida. **La sal** impide las tablas precalculadas, y una función **lenta y
  con mucha memoria** como Argon2id hace muy caro cada intento, incluso con GPU. La práctica pide usar una
  *Password-Based Key Derivation Function* con sal.
- Argon2id ganó la *Password Hashing Competition* y es la recomendación actual. Viene en la misma librería
  `cryptography` (desde la versión 44).
- **T9**, gestión de contraseñas: criterios de calidad (longitud y complejidad), guardar solo el resumen,
  bloqueo ante sospecha de uso fraudulento. Amenazas: fuerza bruta, diccionario y ataque a la base de
  datos ("el talón de Aquiles").

### Dónde está
- `banco/cripto/punto1_autenticacion.py`: `hash_password`, `verificar_password` y `problema_de_password`.
- `banco/banco.py`: `Banco.registrar` y `Banco.iniciar_sesion`.
- `app.py`: sesión, `comprobar_csrf` y `requiere_login`.

### Cómo se demuestra
- **Tests** (`tests/test_punto1_autenticacion.py`): contraseña correcta e incorrecta; misma contraseña →
  resúmenes distintos; la contraseña no aparece en `usuarios.json`; contraseñas débiles rechazadas;
  mismo mensaje para usuario inexistente; bloqueo tras 5 fallos.
- **Laboratorio**: *fuerza bruta contra la contraseña* y *registrarse con una contraseña de diccionario*.
- **Demo**: abrir `datos/usuarios.json` y enseñar el campo `password`: solo hay `sal` y `hash`.

---

## 2. Cifrado y descifrado (autenticado)

> **Enunciado:** *"Siempre que sea posible y tenga sentido su uso, se utilizará cifrado autenticado. [...]
> Importante, evitar claves, IVs o nonces constantes. Los IVs/nonces deberán generarse y gestionarse
> conforme a los requisitos del modo de operación utilizado y nunca reutilizarse."*

### Qué hacemos
- **Algoritmo**: **AES-256-GCM**, cifrado autenticado (AEAD), con clave de **256 bits** y tag de **128 bits**.
- **Nonce**: **96 bits** aleatorios (`os.urandom(12)`), **nuevo en cada cifrado**.
- **Datos asociados (AAD)**: van autenticados pero no cifrados. Atan cada dato a su contexto:
  - estado de la cuenta → `cuenta:<IBAN>`;
  - movimiento → `movimiento:<IBAN>:<id>`;
  - justificante → `justificante:<id>`;
  - clave privada de un cliente → su nombre de usuario.
- **Qué se cifra**: saldo y estado de cada cuenta, movimientos (importe, concepto, contraparte...),
  justificantes guardados y claves privadas.
- Simétrico: el banco cifra y descifra sus propios datos.

### Por qué
- **T3/P2**: **no ECB**, porque bloques iguales dan cifrados iguales y deja ver patrones (P2, ejercicio 2).
  **No CBC sin MAC**: no da integridad, necesita relleno y un IV constante hace que mensajes con el mismo
  principio empiecen igual (P2, ejercicio 1).
- **T4**: GCM es CTR más autenticación (multiplicaciones en GF(2¹²⁸)). Da a la vez confidencialidad,
  integridad y autenticidad. Es lo que pide el enunciado y lo que se ve en P2, ejercicio 5 (`AESGCM`).
- **T3**: AES es el estándar del NIST, elegido "para transferencia de fondos bancarios". Con 256 bits se
  usan 14 rondas.
- **Nonce nunca repetido (T2, T4)**: GCM funciona como un cifrado en flujo, así que con el mismo nonce y
  la misma clave `C1 ⊕ C2 = M1 ⊕ M2` y se podrían falsificar tags. Con 96 bits aleatorios la probabilidad
  de repetición es despreciable para el volumen de esta aplicación.
- **AAD**: si alguien copia el saldo cifrado de una cuenta en otra, el descifrado falla.

### Dónde está
- `banco/cripto/punto2_cifrado.py`: `cifrar`, `descifrar`, `cifrar_json` y `descifrar_json`.
- `banco/banco.py`: `_guardar_estado_cuenta`, `_leer_estado_cuenta`, `_anadir_movimiento` y `_crear_justificante`.

### Cómo se demuestra
- **Tests** (`tests/test_punto2_cifrado.py`): cifrar/descifrar; 1.000 nonces distintos; mismo mensaje →
  cifrados distintos; **ciphertext, tag, nonce o AAD modificados → rechazo**; **clave incorrecta → rechazo**;
  los ficheros no contienen datos en claro; saldo manipulado en el disco → se detecta.
- **Laboratorio**: *cambiar un byte del saldo cifrado* y *copiar el saldo cifrado de otra cuenta*.
- **Demo**: abrir `datos/cuentas.json` (solo `nonce` y `cifrado`), cambiar un carácter de `cifrado` y
  recargar "Mi cuenta" → página de **datos manipulados**.

---

## 3. Generación/verificación de etiquetas de autenticación de mensajes

> **Enunciado:** *"La información de valor que se intercambie o almacene, cuando no se utilice un esquema
> de cifrado autenticado, deberá disponer de un mecanismo de autenticación/integridad adecuado. Es
> recomendable mostrar el resultado en un log [...] junto con el tipo de algoritmo y la longitud de clave."*

### Qué hacemos
- Cada registro ya tiene su tag GCM, pero eso protege cada movimiento **por separado**: no impide borrar
  un movimiento entero ni cambiarlos de orden.
- Por eso cada movimiento lleva además un **HMAC-SHA256** (clave de **256 bits**) calculado sobre:
  - el movimiento **ya cifrado** (Encrypt-then-MAC);
  - el IBAN;
  - **el HMAC del movimiento anterior**.
- Los movimientos forman una **cadena** (un libro de cuentas sellado):
  - modificar, mover o reordenar un movimiento → su HMAC no coincide;
  - borrar un movimiento → no cuadran el número de movimientos ni el "último HMAC", que se guardan cifrados
    en el estado de la cuenta;
  - además se comprueba que el saldo es igual a la suma de los movimientos.
- La clave del HMAC es **distinta** de la de cifrado: las dos se derivan con HKDF (punto 5).
- **Si la verificación falla**, se lanza `ErrorIntegridad`, la web muestra el aviso de **datos manipulados**
  y **no se usan los datos**. El fallo queda anotado en el registro.
- El registro muestra `P3-MAC ... HMAC-SHA256 ... (clave de 256 bits)`.

### Por qué
- **T4**: HMAC(K, M) = H[(K' ⊕ opad) ‖ H[(K' ⊕ ipad) ‖ M]] sobre SHA-256, que no tiene vulnerabilidades
  conocidas (MD5 y SHA-1 están rotos). La seguridad de un MAC es min(2ᵏ, 2ⁿ) = 2²⁵⁶.
- **T4**: *"En caso de que el mensaje incluya un número de secuencia, se evitan ataques por replicación"*.
  El encadenamiento cumple ese papel.
- **T4**: Encrypt-then-MAC es la combinación más segura, y *"la utilización de claves independientes
  (para cifrado y MAC) es modo sólido"*.
- **T7**: la idea es parecida a los árboles de Merkle (cada valor depende del anterior).

### Dónde está
- `banco/cripto/punto3_integridad.py`: `calcular_hmac` y `verificar_hmac`.
- `banco/banco.py`: `_datos_para_hmac`, `_anadir_movimiento` y `_verificar_cuenta`.

### Cómo se demuestra
- **Tests** (`tests/test_punto3_integridad.py`): HMAC correcto; datos modificados u otra clave → rechazo;
  **HMAC modificado**, **movimientos reordenados**, **movimiento intermedio borrado** y **último movimiento
  borrado** → se detectan.
- **Laboratorio**: *borrar un movimiento para ocultar un cargo* y *copiar un movimiento de otra cuenta*.
- **Demo**: borrar un movimiento de `datos/movimientos.json` y recargar "Mi cuenta".

---

## 4. Generación/verificación de firma digital

> **Enunciado:** *"Se utilizarán algoritmos y parámetros actuales (por ejemplo, ECDSA con curvas seguras).
> La aplicación deberá comprobar correctamente el resultado de la verificación y rechazar firmas
> modificadas o inválidas. Las claves privadas deberán almacenarse protegidas. [...] podría ser adecuado que
> las generasen los propios usuarios."*

### Qué hacemos
- **Algoritmo**: **ECDSA** sobre la curva **P-256** con **SHA-256** (clave privada de 256 bits).
- **Firman los propios usuarios**, más allá del mínimo:
  1. **El cliente firma cada orden de transferencia**: id aleatorio, ordenante, cuentas, importe,
     concepto y fecha. Da autenticidad del origen, integridad y **no repudio**.
  2. **El banco firma cada justificante**: incluye la orden firmada por el cliente y la fecha de
     ejecución. Esa fecha firmada funciona como **sello de tiempo** (el banco certifica *cuándo* se ejecutó).
- **Verificación automática**: el banco verifica la firma **antes** de ejecutar nada. Si no es válida, la
  orden se **rechaza** (`OrdenRechazada`), no se mueve dinero y queda en el registro.
- **Verificación a petición del usuario**: la página **"Verificar justificante"** comprueba los dos
  certificados y las dos firmas, y dice cuál falla.
- La orden se serializa en **JSON canónico** (claves ordenadas, sin espacios) para que el mismo contenido
  dé siempre los mismos bytes al firmar y al verificar.

### Por qué
- **Enunciado y T6**: P-256 da unos **128 bits de seguridad**, como RSA-3072 o AES-128 (tabla del T6),
  con claves y firmas mucho más cortas. Es la curva de las suites TLS (`ECDHE-ECDSA-AES128-GCM-SHA256`).
- **T7**: paradigma **"resume y firma"** (SHA-256 y firma del resumen). ECDSA deriva de ElGamal: es un
  esquema **aleatorio con apéndice**. El número secreto de cada firma lo genera la librería; si se repitiera,
  revelaría la clave privada.
- **T7**: la firma **no** da confidencialidad, por eso los datos se cifran aparte (punto 2).
- **P3**: se verifica **exactamente** el mismo mensaje y con el mismo hash con que se firmó (el error del
  ejercicio 1 era verificar `message + b" extra"` con SHA-1). No se usa RSA PKCS#1 v1.5.
- **T10**: cumple la **firma electrónica avanzada** de eIDAS: está vinculada al firmante de forma única, lo
  identifica (certificado), se crea con datos bajo su **control exclusivo** (la clave solo se descifra con
  su contraseña) y detecta cualquier modificación.

### Dónde está
- `banco/cripto/punto4_firma.py`: `generar_par_claves`, `firmar` y `verificar_firma`.
- `banco/banco.py`: `preparar_orden`, `firmar_orden`, `ejecutar_orden` (pasos 1 y 2), `_crear_justificante`
  y `verificar_justificante`.

### Cómo se demuestra
- **Tests** (`tests/test_punto4_firma.py`): firma válida; **mensaje modificado**, **firma alterada** y
  **otra clave** → rechazo; orden con importe modificado → rechazada y no se mueve dinero; justificante
  válido y justificante alterado.
- **Laboratorio**: *modificar el importe de una orden firmada*, *alterar un byte de la firma* y *modificar
  el importe de un justificante*.
- **Demo**: descargar un justificante, verificarlo (✔), cambiar el importe en el JSON y verificarlo otra vez (✘).

---

## 5. Generación y almacenamiento de claves

> **Enunciado:** *"Las claves han de tener una longitud apropiada [...] y generarse de un modo que se
> considere criptográficamente seguro. [...] También es posible no almacenar la clave: [...] si se
> deriva/genera a partir de una contraseña. [...] La clave privada deberá mantenerse confidencial y
> almacenarse protegida; la clave pública [...] cuando sea necesario vincularla de forma fiable con una
> identidad deberá utilizarse [...] certificados y una PKI."*

### Inventario de claves

| Clave | Longitud | Cómo se genera | Dónde se guarda |
|---|---|---|---|
| Clave maestra del banco | 256 bits | **Argon2id** a partir de la **frase maestra** que se escribe al arrancar (sal aleatoria) | **En ningún sitio**: se recalcula en cada arranque |
| Clave de cifrado de datos | 256 bits | **HKDF-SHA256** desde la maestra (`info = "cifrado de datos"`) | Solo en memoria |
| Clave del HMAC | 256 bits | **HKDF-SHA256** desde la maestra (`info = "hmac de movimientos"`) | Solo en memoria |
| Clave de la CA del banco | ECDSA P-256 | `ec.generate_private_key` | PKCS#8 cifrado con AES-256-GCM (clave de datos) |
| Clave de firma de justificantes | ECDSA P-256 | `ec.generate_private_key` | PKCS#8 cifrado con AES-256-GCM (clave de datos) |
| Clave privada de cada cliente | ECDSA P-256 | `ec.generate_private_key` al registrarse | PKCS#8 cifrado con AES-256-GCM con una clave **derivada de su contraseña** (Argon2id, sal propia) |
| Claves públicas | ECDSA P-256 | Junto a la privada | Dentro de **certificados X.509** firmados por la CA |
| Sales y nonces | 128 / 96 bits | `os.urandom` (generador seguro del sistema) | Junto a los datos (no son secretos) |
| Clave de la cookie de sesión | 256 bits | `secrets.token_bytes(32)` en cada arranque | Solo en memoria |

### Qué hacemos y por qué
- **Ninguna clave simétrica se guarda**: se derivan de contraseñas (opción que da el enunciado).
- **Una subclave por uso (HKDF)**: claves independientes para cifrado y MAC (T4). El T6 recuerda que
  "no se usa K como clave simétrica, sino K' = KDF(K)".
- **Comprobación de la frase maestra**: al arrancar se descifra un texto conocido. Si el tag de GCM falla,
  la frase es incorrecta y el banco **no arranca**.
- **Clave privada del cliente protegida con su contraseña**: para firmar una transferencia hay que escribir
  la contraseña, que es lo que la descifra en ese momento. **Ni el propio banco puede firmar en nombre del
  cliente**. Esto cumple el "control exclusivo" (eIDAS) y que el prestador "no almacene datos de creación de
  firma" (Ley 6/2020), ambos del T10.
- **Cada clave tiene un único uso**: la CA solo firma certificados y la clave de justificantes solo firma
  justificantes.
- **Longitudes**: AES-256 y HMAC con claves de 256 bits; ECDSA P-256 ≈ 128 bits de seguridad, por encima
  del mínimo aceptable de 2¹¹² (T4).
- **Aleatoriedad (T2)**: todo sale de `os.urandom` o `secrets`, nunca de `random`.
- **Nada en el código**: no hay claves, IVs ni nonces constantes (errores de P2). El repositorio no contiene
  secretos: todo se genera al ejecutar y la carpeta `datos/` está en `.gitignore`.

### Certificados y PKI (T8, P4)
- El banco tiene su propia **autoridad de certificación (CA)**: certificado X.509 autofirmado,
  `BasicConstraints ca=True`, `keyUsage = keyCertSign, cRLSign`, válido 5 años.
- Al registrarse, cada cliente recibe un **certificado X.509** que vincula su nombre con su clave pública:
  `ca=False`, `keyUsage = digitalSignature, contentCommitment` (no repudio), válido **1 año**. La Ley 6/2020
  pide menos de 5 años para los certificados cualificados (T10).
- **Verificación de un certificado** (`verificar_certificado`). Como enseña P4, *una firma válida no basta*;
  se comprueba:
  1. que lo ha firmado la CA del banco;
  2. que está dentro de su periodo de validez;
  3. que el nombre es el del ordenante (el caso `attacker.com` de P4);
  4. que no es de CA y que su `keyUsage` permite firmar.

### Dónde está
- `banco/cripto/punto5_claves.py`: `derivar_clave_de_password`, `derivar_subclave`,
  `proteger_clave_privada` y `recuperar_clave_privada`.
- `banco/cripto/punto5_certificados.py`: `crear_certificado_ca`, `emitir_certificado` y `verificar_certificado`.
- `banco/banco.py`: `_derivar_claves`, `_crear_banco`, `_abrir_banco`, `registrar` y `firmar_orden`.

### Cómo se demuestra
- **Tests** (`tests/test_punto5_claves.py`): derivación determinista de 256 bits; HKDF da subclaves
  distintas; clave privada recuperable solo con la clave correcta; **frase maestra incorrecta → no
  arranca**; ningún secreto en los ficheros; **firmar con contraseña incorrecta → imposible**;
  certificados de otra persona, de otra CA, caducados o de CA → rechazados.
- **Laboratorio**: *firmar en nombre de Ana con el certificado de Eva*, *certificado de una CA falsa*,
  *firmar sin la contraseña* y *arrancar el banco sin la frase maestra*.
- **Demo**: parar el banco y arrancarlo con una frase incorrecta.

---

## 6. Otras consideraciones del enunciado

| Enunciado | Cómo se cumple |
|---|---|
| *"Fuentes de aleatoriedad criptográficamente seguras"* | `os.urandom` y `secrets` para claves, sales, nonces e identificadores |
| *"Un MAC, tag o firma inválidos deben provocar el rechazo de los datos"* | `ErrorIntegridad` / `OrdenRechazada`: no se muestran ni se usan los datos y no se mueve dinero |
| *"Pruebas negativas: ciphertext/tag/MAC modificado, firma alterada, clave o contraseña incorrecta y [...] repetición de mensajes"* | Todas están en los tests y en el laboratorio (sección 8) |
| *"Dependencias criptográficas con su versión"* | `requirements.txt`: `cryptography==46.0.3` (única librería criptográfica) |

### Repetición de mensajes (replay) (P3, pregunta 2)
- Cada orden lleva un **identificador aleatorio de 128 bits** y la **fecha**, ambos **dentro de lo firmado**.
- El banco rechaza una orden si su identificador ya está en los movimientos (protegidos con HMAC: no se
  puede borrar el rastro) o si tiene más de **5 minutos**.
- **Tests**: `tests/test_repeticion.py`. **Laboratorio**: *repetir una orden ya ejecutada* y *presentar una
  orden firmada hace una hora*.

---

## 7. Calidad del software

| Requisito del enunciado | Cómo se cumple |
|---|---|
| Código estructurado y legible | Un archivo por punto del enunciado; funciones cortas; nombres y comentarios en español |
| Separación entre lógica y criptografía | `banco/cripto/` (criptografía) ↔ `banco/banco.py` (lógica) ↔ `app.py` (interfaz) |
| Validación de entradas | Usuario, contraseña, IBAN, importe (céntimos enteros, máx. 2 decimales), concepto y tamaño de petición |
| Tratamiento de excepciones | Errores propios (`ErrorBanco`, `ErrorIntegridad`, `OrdenRechazada`, `ErrorCriptografico`) con mensajes claros, sin filtrar detalles internos |
| Pruebas reproducibles | `python -m pytest`: 94 pruebas; cada una crea su banco en una carpeta temporal |
| Fallar de forma segura | Ante datos manipulados o credenciales incorrectas no se muestra ni se ejecuta nada |
| Sin secretos en el repositorio | `.gitignore` excluye `datos/`; claves generadas al ejecutar; frase maestra por teclado |

---

## 8. Ataques relevantes y cómo se mitigan

Todos se lanzan desde la página **Laboratorio de ataques** y están automatizados en `tests/test_laboratorio.py`.

| Punto | Ataque | Amenaza (T1) | Mitigación |
|---|---|---|---|
| P1 | Fuerza bruta contra una contraseña | Generación (suplantación) | Argon2id + bloqueo tras 5 fallos |
| P1 | Contraseña de diccionario | Generación | Política de contraseñas robustas |
| P2 | Cambiar un byte del saldo cifrado | Modificación → integridad | Tag AES-GCM |
| P2 | Copiar el saldo cifrado de otra cuenta | Modificación | AAD = IBAN |
| P3 | Borrar un movimiento para ocultar un cargo | Modificación | HMAC encadenado + contador cifrado |
| P3 | Copiar un movimiento de otra cuenta | Modificación | HMAC que incluye el IBAN |
| P4 | Cambiar el importe de una orden firmada | Modificación | Firma ECDSA |
| P4 | Alterar la firma | Modificación | Verificación ECDSA |
| P4 | Modificar un justificante | Modificación | Firma del banco y del cliente |
| P5 | Firmar como Ana con el certificado de Eva | Generación (suplantación) | Certificado: identidad |
| P5 | Certificado de una CA falsa | Generación (suplantación) | Certificado: firma de la CA del banco |
| P5 | Firmar sin la contraseña de Ana | Generación | Clave privada cifrada con la contraseña |
| P5 | Arrancar el banco sin la frase maestra | Interceptación (robo de datos) | Clave maestra derivada, no guardada |
| Replay | Repetir una orden ejecutada | Generación | Id único dentro de lo firmado |
| Replay | Presentar una orden antigua | Generación | Fecha firmada + caducidad |

Otros riesgos considerados: **robo del fichero de datos** (todo cifrado o como resumen Argon2id),
**diccionario sin conexión** (sal + Argon2id), **CSRF** (token por sesión) y **enumeración de usuarios**
(mensaje genérico y mismo tiempo de respuesta).

---

## 9. Limitaciones (mejoras para un sistema real)

- Funciona en local con HTTP y el servidor de desarrollo de Flask. En producción iría con **HTTPS (TLS 1.3)**,
  cuyo handshake ECDHE da secreto hacia delante (T6), y con un servidor WSGI.
- Las firmas de los clientes se calculan en el servidor, aunque con una clave que solo se descifra con su
  contraseña. En un sistema real se harían en el dispositivo del cliente, una tarjeta o un HSM (T8). Sería
  necesario para una firma **cualificada** (eIDAS).
- No hay revocación de certificados (CRL u OCSP, T8) ni CA intermedia.
- No hay segundo factor: el **OTP síncrono/TOTP** del T9, que PSD2 exige para pagos, sería la siguiente mejora.
- ECDSA sería vulnerable a un ordenador cuántico (algoritmo de Shor). La alternativa post-cuántica es
  **ML-DSA** (T7).
- Ficheros JSON y un cerrojo en memoria: válidos para una demo, no para muchos usuarios a la vez.

---

## 10. Dependencias e instalación

| Librería | Versión | Uso |
|---|---|---|
| `cryptography` | 46.0.3 | **Toda** la criptografía (la misma librería de las prácticas de clase) |
| `Flask` | 3.1.2 | Interfaz web |
| `pytest` | 8.4.2 | Pruebas |

Los pasos de instalación desde un entorno limpio están en el [`README.md`](README.md).

---

## 11. Correspondencia con las preguntas de la memoria

| Pregunta del entregable | Sección de este documento |
|---|---|
| Propósito y estructura interna | 0 |
| Autenticación de usuarios | 1 |
| Cifrado simétrico/asimétrico, claves, IVs y nonces | 2 y 5 |
| Integridad y autenticidad (MAC/AEAD) | 2 y 3 |
| Firma digital (y prueba de firma rechazada) | 4 |
| Pruebas y al menos tres ataques | 6, 7 y 8 |
| Librerías, versiones e instalación | 10 |
