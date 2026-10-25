# LogVault — Taller Dos: Criptografía (protección de logs en reposo)

CLI en Go que genera un log JSON de eventos de registro/modificación de notas,
hashea cada evento y el log completo (SHA-256), lo cifra (AES-256-GCM),
lo descifra y verifica que la información original se preservó.

## Requisitos
- Go 1.22+
- Única dependencia de terceros: `github.com/manifoldco/promptui` (menús en terminal).
  Hashing y cifrado usan **solo la biblioteca estándar** (`crypto/sha256`, `crypto/aes`,
  `crypto/cipher`, `crypto/rand`).

## Uso
```bash
go mod tidy                 # descarga promptui y genera go.sum
go run ./cmd/logvault       # menú interactivo; artefactos en ./output
go run ./cmd/logvault -out /ruta/salida
```

## Pruebas
```bash
go vet ./...
go test -race -cover ./...
```

## Artefactos generados (`output/`)
| Archivo | Paso | Contenido |
|---|---|---|
| `log.json` / `log.json.sha256` | 4-5 | Log en claro y su hash |
| `log.enc` / `log.enc.sha256` | 6-7 | Log cifrado y su hash |
| `key.hex` (0600), `nonce.hex` | 6 | Insumos criptográficos |
| `log.decrypted.json` / `log.decrypted.sha256` | 8-9 | Log recuperado y su hash |

Los `.sha256` usan formato `sha256sum`: `cd output && sha256sum -c log.json.sha256`.

## Estructura
```
cmd/logvault/        punto de entrada
internal/domain/     Payload, Event, Log
internal/generator/  eventos aleatorios (UIDs, notas U(0,5))
internal/integrity/  SHA-256: payload, log, verificación
internal/cryptoutil/ AES-256-GCM
internal/storage/    lectura/escritura de artefactos
internal/pipeline/   orquesta los pasos 1-10
internal/cli/        menú (interfaz Prompter + adaptador promptui)
docs/diagramas/      diagramas de estructura y comportamiento (Mermaid)
```
