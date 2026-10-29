# Protección de logs académicos en reposo

Proyecto del Taller Dos de Criptografía. Incluye el flujo CLI original y una interfaz web local para presentar los eventos, hashes y verificaciones.

## Ejecutar la interfaz web

Desde esta carpeta del proyecto:

```powershell
go run ./cmd/criptografia -web
```

Abre <http://127.0.0.1:8080>. Para cambiar el directorio de artefactos o el puerto:

```powershell
go run ./cmd/criptografia -web -out output -addr 127.0.0.1:8080
```

El servidor escucha solo en `127.0.0.1` por defecto. Para detenerlo usa `Ctrl+C` en la terminal. El menú original sigue disponible con `go run ./cmd/criptografia`.

## Qué muestra la interfaz

- Cantidad, tipo y lista de eventos generados, con nota anterior/nueva para modificaciones.
- Hash SHA-256 por evento y los hashes del log original, cifrado y descifrado.
- Comparación del original con el descifrado y botón para verificar artefactos.
- Simulación de manipulación del ciphertext en memoria: muestra la detección por hash y por autenticación GCM; no modifica el archivo almacenado.

Los artefactos criptográficos quedan en `output/` (o el directorio indicado con `-out`), según el flujo existente. La llave AES se guarda como parte del ejercicio y debe protegerse: quien la obtenga junto con el ciphertext puede descifrarlo.

## Conexión frontend/backend

La página está en `internal/webui/static/` y se incorpora al ejecutable mediante `embed`. El paquete `internal/webui` publica `POST /api/run`, `POST /api/verify` y `POST /api/tamper`; todos delegan las operaciones criptográficas en `internal/flujo`, sin replicar el cifrado ni el hashing en JavaScript.
