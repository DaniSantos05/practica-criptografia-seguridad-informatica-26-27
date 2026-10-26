# Contexto para Claude Code

Práctica final de Criptografía y Seguridad Informática (UC3M 26/27), por parejas.
Se evalúa más la **defensa** (20%) que la entrega (10%): el código debe ser sencillo, legible y con
comentarios claros en español. No añadir complejidad innecesaria.

- Lee `DISENO.md` antes de cambiar nada: ahí están todas las decisiones y su justificación.
- Toda la criptografía va en `banco/cripto.py`; la lógica en `banco/banco.py`; la web en `app.py`.
- Única librería criptográfica: `cryptography`.
- Ejecutar tests: `python -m pytest -q` (todos deben pasar).
- Nunca registrar ni mostrar claves, contraseñas u otros secretos.
