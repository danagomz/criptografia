# Diagrama de estructura (paquetes y dependencias)

Renderizar en https://mermaid.live y exportar a PNG/SVG para el ZIP.

```mermaid
classDiagram
    direction LR

    class main {
        <<cmd/proteccion-logs>>
        +main()
    }

    class cli_App {
        <<internal/menu>>
        -prompter Prompter
        -runner Runner
        +Run() error
    }
    class Prompter {
        <<interface>>
        +Select(label, items) int
        +Ask(label, validate) string
    }
    class PromptUI {
        <<promptui, 3ros>>
    }

    class Pipeline {
        <<internal/flujo>>
        +Run(count) Result
        +VerifyStored() error
        +SimulateTampering() TamperReport
    }

    class Generator {
        <<internal/generador>>
        +Generate(count) Payload[]
    }
    class integrity {
        <<internal/integridad — SHA-256>>
        +SHA256Hex(data) string
        +PayloadHash(payload) string
        +NewEvent(payload) Event
        +VerifyLog(log) error
    }
    class cryptoutil {
        <<internal/cifrado — AES-256-GCM>>
        +NewMaterial() Material
        +Encrypt(material, plain, aad) bytes
        +Decrypt(material, cipher, aad) bytes
    }
    class Store {
        <<internal/almacenamiento>>
        +Write(name, data, perm)
        +Read(name) bytes
    }
    class domain {
        <<internal/modelo>>
        Payload
        Event
        Log
    }

    main --> cli_App
    main --> Pipeline
    cli_App --> Prompter
    PromptUI ..|> Prompter
    cli_App --> Pipeline : Runner
    Pipeline --> Generator
    Pipeline --> integrity
    Pipeline --> cryptoutil
    Pipeline --> Store
    Generator --> domain
    integrity --> domain
    Pipeline --> domain
```
