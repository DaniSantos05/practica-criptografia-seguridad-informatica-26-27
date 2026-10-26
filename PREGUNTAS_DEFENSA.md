# Preparación de la defensa: preguntas probables

Respuestas cortas, para decirlas en voz alta. Entre corchetes, dónde está en el código o en los apuntes.
La explicación completa de cada decisión está en [`DISENO.md`](DISENO.md).

---

## Generales

**¿Qué hace vuestra aplicación?**
Una banca online ficticia: registro, login, saldo y movimientos, transferencias firmadas por el cliente y
justificantes firmados por el banco. Cada requisito del enunciado tiene su archivo en `banco/cripto/`.

**¿Dónde está la criptografía?**
Toda en `banco/cripto/`, un archivo por punto del enunciado. `banco.py` solo la usa y `app.py` es la web.

**¿Qué librería usáis y por qué?**
Solo `cryptography` 46.0.3, la misma de las prácticas de clase. No implementamos ningún algoritmo nosotros:
implementar criptografía a mano es una fuente de errores (P4, pregunta 5e).

---

## Punto 1 · Autenticación

**¿Cómo guardáis las contraseñas?**
No las guardamos. Guardamos su resumen Argon2id con una sal aleatoria de 128 bits por usuario
(t=3, m=64 MiB, p=4, 256 bits de salida). [`punto1_autenticacion.py`]

**¿Por qué no SHA-256?**
Porque es rápido: un atacante prueba miles de millones por segundo con GPU, y sin sal la misma contraseña
da el mismo hash, así que se puede usar un diccionario o tablas precalculadas (P1). Argon2id es lento y
gasta memoria a propósito.

**¿Para qué sirve la sal?**
Para que dos usuarios con la misma contraseña tengan resúmenes distintos y no se puedan usar tablas
precalculadas. No es secreta: se guarda junto al resumen.

**¿Por qué Argon2id y no bcrypt o PBKDF2?**
Es la recomendación actual (ganó la Password Hashing Competition) y además de tiempo consume memoria, lo
que dificulta los ataques con GPU o ASIC. bcrypt y PBKDF2 también serían aceptables.

**¿Qué hacéis contra la fuerza bruta?**
Argon2id hace caro cada intento sin conexión, y en línea la cuenta se bloquea 5 minutos tras 5 fallos.

**¿Por qué el mismo mensaje si el usuario no existe?**
Para no revelar qué usuarios existen. Por eso también calculamos un Argon2id aunque no exista: así tarda lo mismo.

**¿Qué es el token CSRF?**
Un valor aleatorio por sesión que va en cada formulario. Una web maliciosa no lo conoce, así que no puede
enviar formularios en nombre del usuario.

**¿Qué otros factores de autenticación existen?**
Algo que tienes (token, OTP como TOTP) y algo que eres (biometría) (T9). TOTP sería nuestra siguiente mejora.

---

## Punto 2 · Cifrado

**¿Qué algoritmo y modo usáis?**
AES-256-GCM, cifrado autenticado (AEAD): confidencialidad e integridad en una sola operación. [`punto2_cifrado.py`]

**¿Por qué no ECB?**
Bloques iguales dan cifrados iguales: se ven patrones y se pueden reordenar bloques (P2, ejercicio 2).

**¿Por qué no CBC?**
No da integridad (habría que añadir un MAC), necesita relleno y ha tenido ataques (padding oracle). Además,
con IV constante dos mensajes con el mismo principio empiezan igual (P2, ejercicio 1).

**¿Cómo generáis el nonce? ¿Qué pasa si se repite?**
96 bits aleatorios con `os.urandom` en cada cifrado. Si se repitiera con la misma clave, como GCM es un
modo contador, C1 ⊕ C2 = M1 ⊕ M2 (T2) y además se podrían falsificar tags.

**¿Qué es el AAD y para qué lo usáis?**
Datos que no se cifran pero sí se autentican. Usamos el IBAN: si alguien copia el saldo cifrado de una
cuenta en otra, el tag no coincide.

**¿Qué pasa si alguien modifica un byte del fichero de datos?**
Falla el tag de GCM, se lanza `ErrorIntegridad`, no se muestran los datos y queda en el registro. (Demo y laboratorio P2.)

**¿Usáis cifrado asimétrico?**
Para cifrar no: todo lo cifra y descifra el banco, así que el simétrico es lo adecuado (y mucho más rápido,
T5). La criptografía asimétrica la usamos en la firma y los certificados. El enunciado pide "simétrico y/o asimétrico".

**¿Qué diferencia hay entre AES-GCM y Fernet?**
Fernet es AES-128-CBC más HMAC-SHA256 (Encrypt-then-MAC) con marca de tiempo. GCM es un AEAD nativo, más
eficiente y con datos asociados.

---

## Punto 3 · MAC

**Si ya usáis GCM, ¿para qué el HMAC?**
GCM protege cada movimiento por separado, pero no impide borrar uno entero o cambiar el orden. El HMAC
encadenado (cada HMAC incluye el anterior) protege la lista completa. [`punto3_integridad.py`, `_verificar_cuenta`]

**¿Cómo se detecta que se ha borrado el último movimiento?**
El estado cifrado de la cuenta guarda cuántos movimientos hay y el HMAC del último. Si no coinciden → manipulación.

**¿Por qué claves distintas para cifrar y para el HMAC?**
Porque usar claves independientes es la forma sólida de construir cifrado autenticado (T4). Las derivamos
con HKDF de la clave maestra.

**¿Qué es Encrypt-then-MAC?**
Calcular el MAC sobre el texto ya cifrado. Así se puede verificar sin descifrar, y es la variante más segura (T4).

**¿Cómo se calcula un HMAC?**
HMAC(K, M) = H[(K' ⊕ opad) ‖ H[(K' ⊕ ipad) ‖ M]], con SHA-256 y clave de 256 bits.

**¿Por qué comparar en tiempo constante?**
Una comparación normal se detiene en el primer byte distinto, y midiendo el tiempo un atacante podría
adivinar el MAC byte a byte.

---

## Punto 4 · Firma digital

**¿Qué algoritmo y por qué?**
ECDSA con P-256 y SHA-256: unos 128 bits de seguridad (como RSA-3072, T6) con claves mucho más cortas. Es
el ejemplo que da el enunciado. [`punto4_firma.py`]

**¿Qué se firma y quién lo firma?**
El cliente firma cada orden de transferencia y el banco firma cada justificante (con la orden firmada y la fecha).

**¿Qué aporta la firma que no aporta un HMAC?**
No repudio: el HMAC lo puede calcular cualquiera que tenga la clave (el banco y el cliente), la firma solo
el dueño de la clave privada. Además cualquiera puede verificarla con la clave pública.

**¿Qué pasa si se cambia el importe de una orden firmada?**
La firma no coincide, la orden se rechaza y no se mueve dinero. (Laboratorio P4.)

**¿La firma da confidencialidad?**
No (T7). Por eso los datos se cifran aparte con AES-GCM.

**¿Qué significa "resume y firma"?**
Primero se calcula SHA-256 de los datos y se firma el resumen: es más eficiente y más seguro (T7).

**¿ECDSA es determinista?**
No, es aleatorio: cada firma usa un número secreto nuevo. Si se repitiera, se podría calcular la clave
privada (le pasó a Sony con la PS3). Lo genera la librería de forma segura.

**¿Por qué JSON canónico?**
Para que el mismo contenido se convierta siempre en los mismos bytes: si al verificar el orden de los
campos fuera distinto, la firma fallaría.

**¿Por qué no RSA con PKCS#1 v1.5?**
Para firmas con RSA se recomienda PSS (P3). Nosotros usamos ECDSA.

**¿Qué es el sello de tiempo del justificante?**
La fecha de ejecución firmada por el banco: el banco certifica cuándo ocurrió. Un sello es más que una
marca de tiempo porque lo firma un tercero de confianza (T7).

---

## Punto 5 · Claves

**¿Dónde se guarda la clave de cifrado del banco?**
En ningún sitio. Se deriva con Argon2id de la frase maestra que se escribe al arrancar, y de ella salen
con HKDF la clave de cifrado y la del HMAC. [`punto5_claves.py`, `Banco._derivar_claves`]

**¿Cómo sabéis que la frase maestra es correcta?**
Al crear el banco se cifra un texto conocido. Al arrancar se intenta descifrar: si el tag falla, la frase
es incorrecta y el banco no arranca.

**¿Dónde se guardan las claves privadas?**
En formato PKCS#8 cifradas con AES-256-GCM. Las del banco, con la clave de datos. La de cada cliente, con
una clave derivada de su propia contraseña.

**¿Puede el banco firmar en nombre de un cliente?**
No: su clave privada está cifrada con una clave derivada de la contraseña del cliente, que el banco no
guarda. Por eso se pide la contraseña al transferir (control exclusivo, eIDAS, T10).

**¿Para qué sirve HKDF?**
Para obtener varias claves independientes de una clave maestra, una por cada uso (el parámetro `info` las
diferencia).

**¿Qué longitudes de clave usáis y por qué son suficientes?**
AES-256 y HMAC con 256 bits; ECDSA P-256 (≈128 bits de seguridad). Todas superan el mínimo de 2¹¹² (T4).

**¿Cómo se generan las claves y los nonces?**
Con `os.urandom` y `secrets` (generador del sistema operativo), nunca con `random`, que es predecible.

**¿Para qué sirven los certificados?**
Para saber de quién es una clave pública. La CA del banco firma un certificado X.509 por cliente que dice
"esta clave pública es de Ana". [`punto5_certificados.py`]

**¿Basta con comprobar la firma del certificado?**
No (P4). Comprobamos que lo firmó nuestra CA, que está vigente, que es de la persona que firma la orden
(si no, Eva podría usar su propio certificado válido) y que su `keyUsage` permite firmar.

**¿Qué es keyUsage y BasicConstraints?**
`keyUsage` dice para qué puede usarse la clave (la CA solo para firmar certificados; los clientes, para
firmar documentos con no repudio). `BasicConstraints` dice si el certificado es de una CA.

**¿Por qué el certificado del cliente dura un año?**
Validez acotada como medida preventiva (T8). La Ley 6/2020 limita los certificados cualificados a menos de 5 años.

**¿Y si roban la clave privada de un cliente?**
Habría que revocar su certificado (CRL u OCSP, T8). No lo hemos implementado: está en las limitaciones.

---

## Repetición y pruebas

**¿Qué es un ataque de replay y cómo lo evitáis?**
Reenviar un mensaje válido capturado, por ejemplo una orden de 50 € diez veces. Cada orden lleva un id
aleatorio y una fecha dentro de lo firmado: el banco rechaza ids ya ejecutados y órdenes de más de 5 minutos.

**¿Cómo sabéis qué órdenes se han ejecutado? ¿No podría un atacante borrar ese registro?**
El id de la orden se guarda dentro de los movimientos, que están cifrados y encadenados con HMAC: borrarlo
rompería la cadena.

**¿Qué pruebas habéis hecho?**
94 pruebas automáticas, organizadas por punto del enunciado, positivas y negativas: ciphertext, tag, nonce,
AAD y MAC modificados; firma alterada; clave o contraseña incorrecta; certificados falsos o caducados;
repetición de órdenes. Además, 15 ataques reales en el laboratorio.

**Nombrad tres ataques y cómo los mitigáis.**
1. Robo del fichero de datos → todo cifrado con AES-GCM y contraseñas con Argon2id + sal.
2. Modificar una orden firmada o un justificante → firma ECDSA, se rechaza.
3. Repetir una orden → id único dentro de lo firmado.
4. Suplantar a otro cliente → certificado X.509 verificado contra la CA y el nombre del ordenante.

---

## Errores de las prácticas de clase que hemos evitado

| Error (práctica) | Cómo lo evitamos |
|---|---|
| SHA-256 sin sal para contraseñas (P1) | Argon2id + sal de 128 bits |
| Clave escrita en el código (P2) | Claves derivadas de la frase maestra; nada en el código |
| IV constante (P2) | Nonce aleatorio nuevo en cada cifrado |
| Relleno con espacios / CBC sin integridad (P2) | AES-GCM: sin relleno y con integridad |
| ECB (P2) | Nunca |
| Verificar otro mensaje o con otro hash (P3) | Se verifica el mismo JSON canónico con SHA-256 |
| Firma sin protección contra repetición (P3) | Id único + fecha dentro de lo firmado |
| Verificar solo la firma del certificado (P4) | Además: emisor, fechas, identidad y keyUsage |
