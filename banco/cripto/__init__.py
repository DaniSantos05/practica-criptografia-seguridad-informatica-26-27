"""
Criptografía de BancoSeguro, organizada según los puntos del enunciado.

TODA la criptografía de la aplicación está en esta carpeta. El resto del código
(banco.py, app.py...) solo llama a estas funciones.

  punto1_autenticacion.py  -> 1. Registro y autenticación de usuarios (Argon2id)
  punto2_cifrado.py        -> 2. Cifrado/descifrado autenticado (AES-256-GCM)
  punto3_integridad.py     -> 3. Etiquetas de autenticación de mensajes (HMAC-SHA256)
  punto4_firma.py          -> 4. Generación/verificación de firma digital (ECDSA P-256)
  punto5_claves.py         -> 5. Generación y almacenamiento de claves (Argon2id, HKDF, PKCS#8)
  punto5_certificados.py   -> 5. Vincular clave pública e identidad: certificados X.509 y PKI
  comun.py                 -> Utilidades compartidas (sales aleatorias, JSON canónico, errores)

Única librería criptográfica: "cryptography" (la misma de las prácticas de clase).
"""
