# Contexto para Claude Code

Práctica final de Criptografía y Seguridad Informática (UC3M 26/27), por parejas.
Se evalúa más la **defensa** (20%) que la entrega (10%): el código debe ser sencillo, legible y con
comentarios claros en español. No añadir complejidad innecesaria.

Al profesor le importa la criptografía que pide el enunciado, no la app: todo se organiza según los
puntos del enunciado (1. autenticación, 2. cifrado, 3. MAC, 4. firma, 5. claves).

- Lee `DISENO.md` antes de cambiar nada: ahí está cómo se cumple cada punto y por qué.
- `PREGUNTAS_DEFENSA.md`: preguntas probables de la defensa con su respuesta.
- Toda la criptografía va en `banco/cripto/` (un archivo por punto: `punto1_autenticacion.py` ...
  `punto5_certificados.py`); la lógica en `banco/banco.py`; la web en `app.py`.
- Tests por punto: `tests/test_punto1_...` a `tests/test_punto5_...`.
- El registro de seguridad etiqueta cada línea con su punto (P1-AUTENTICACION, P2-CIFRADO, P3-MAC, P4-FIRMA, P5-CLAVES, P5-PKI).
- Única librería criptográfica: `cryptography`.
- Ejecutar tests: `python -m pytest -q` (todos deben pasar).
- Nunca registrar ni mostrar claves, contraseñas u otros secretos.
