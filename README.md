# Ominous Security

Herramienta web local (http://localhost:8080) que analiza un repositorio de GitHub **antes de clonarlo**.

## Cómo arrancarla

Requisitos: Node.js 18 o superior y git. Funciona sin instalar nada; `npm install` solo añade el SDK de Anthropic para los resúmenes por IA.

```bash
cd ominous-security
npm install             # opcional: resúmenes del diff con Claude
node server.js          # o: npm start
```

Abre http://localhost:8080, pega la URL del repo y pulsa **Analizar**.

Variables opcionales:

| Variable | Para qué |
|---|---|
| `PORT` | Puerto (por defecto 8080) |
| `CLONE_DIR` | Carpeta donde se clonan los repos (por defecto `~/ominous-clones`) |
| `GITHUB_TOKEN` | Evita el límite de la API de GitHub al leer la reputación del autor |
| `HOST=0.0.0.0` + `ALLOW_ANY_HOST=1` | Abrirla desde el móvil en tu red local. Ojo: cualquiera de tu red podría usarla para clonar en tu disco |

## Qué hace

1. **Descarga** el repo (`git clone --depth 1`) en una carpeta temporal con git endurecido: sin hooks, sin submódulos, sin LFS. **Nunca ejecuta nada del repo.** La carpeta temporal se borra al terminar.
2. **Vulnerabilidades del código**: unas 50 reglas (JS/TS, Python, PHP, Go, Java, Ruby, shell, Docker, GitHub Actions), secretos expuestos y dependencias con vulnerabilidades conocidas (consulta a OSV.dev para npm, PyPI y Go). Cada una indica si **la puedo arreglar** (con la solución) o **no** (con el motivo). Las marcadas como *automático al clonar* se aplican si marcas la casilla al clonar. Lo que está en carpetas de tests/ejemplos/docs se rebaja a informativo.
3. **Amenazas deliberadas**: scripts `postinstall`/`setup.py`, tareas de VS Code que se ejecutan al abrir la carpeta, devcontainers, git hooks, `curl | sh`, reverse shells, mineros, robo de credenciales (navegador, Discord, carteras, SSH/AWS), webhooks de exfiltración, persistencia, desactivación del antivirus, Trojan Source (Unicode bidi), código escondido tras cientos de espacios, binarios disfrazados de imagen, symlinks fuera del repo, typosquatting y cuentas nuevas con estrellas infladas.
3b. **Más vectores**: ficheros que se ejecutan solos (`conftest.py`, `.pth`, `sitecustomize.py`, `build.rs`, Gradle/Maven, `.envrc`, pre-commit, configs de webpack/jest/eslint, ajustes de VS Code que apuntan a ejecutables, hooks de Claude Code y servidores MCP del proyecto), instrucciones peligrosas para agentes de IA (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`…) y texto Unicode invisible, lockfiles que descargan de servidores no oficiales, registros de paquetes alternativos (dependency confusion), dependencias catalogadas como malware en OSV, READMEs que piden descargar un zip con contraseña, ZIP cifrados o con ejecutables, dobles extensiones (`factura.pdf.exe`), homoglifos, keyloggers, clippers de criptomonedas, diálogos falsos de contraseña, puertas traseras SSH, comandos destructivos y borrado de rastros.
3c. **Historial de git**: revisa las líneas borradas de los últimos 300 commits (`HISTORY_COMMITS`) en busca de secretos y código malicioso que se quitó pero sigue en el repo.
3d. **Submódulos**: comprueba sus URL y analiza hasta 8 en el commit exacto que fija el repo. **Releases**: avisa de binarios publicados que no se pueden revisar.
3e. **Cobertura**: cada análisis muestra qué se ha revisado por completo, qué parcialmente y qué no.
4. **Ingeniería inversa de scripts ocultos**, sin ejecutarlos: pela capas de base64, hex, zlib/gzip/deflate, `String.fromCharCode`, cadenas invertidas, XOR de un byte (fuerza bruta) y **Fernet (AES) cuando la clave está en el propio repo**. El código descifrado se vuelve a analizar y se muestra en claro. Si un payload está cifrado con una clave que no está en el repo, se marca como no descifrable.
5. **Diff y resumen de los arreglos**: si clonas con arreglos automáticos, la app muestra el diff exacto (`git diff`) y un resumen que explica cada cambio, por qué es más seguro y qué podría romper. El resumen lo redacta Claude si instalas el SDK (`npm install`) y tienes credenciales (`ANTHROPIC_API_KEY` o `ant auth login`); sin eso se genera un resumen local a partir de las reglas. El contenido del repo se envía a la API de Anthropic solo en ese caso. El botón **Deshacer los arreglos** deja el clon igual que en GitHub. Variable opcional `OMINOUS_MODEL` para cambiar el modelo (por defecto `claude-opus-5-5`).
6. **Clonar**: botón al final. Si el resultado no está en verde, exige marcar la casilla de confirmación (también lo comprueba el servidor). El clon se fija al commit exacto que se analizó, aunque el autor haya subido cambios después.

## Seguridad del propio servidor

- Solo escucha en `127.0.0.1` y rechaza peticiones con otro `Host` (protección contra DNS rebinding) o desde otras webs (`Origin`).
- Las URLs se validan de forma estricta y git se invoca sin shell.

## Límites

Es análisis estático por patrones: reduce mucho el riesgo, pero no es una garantía. Un atacante decidido puede esquivar reglas concretas o descargar el payload real en tiempo de ejecución desde un servidor (eso sí se marca, pero no se puede ver qué descargará). Analiza hasta 8000 ficheros de 1,5 MB como máximo. El análisis corre en un hilo aparte con un tiempo máximo de 5 minutos (`ANALYSIS_TIMEOUT_MS`), para que un fichero diseñado para bloquear analizadores no deje colgada la app.

Si analizas esta propia herramienta saldrá en rojo: `lib/rules.js` contiene las firmas que busca, igual que un antivirus.

## Escáner por línea de comandos

Analiza una carpeta local sin servidor, útil en CI de cualquier proyecto:

```bash
node bin/ominous-scan.js <carpeta> [--exclude ruta1,carpeta/] [--fail-on red|yellow|never] \
     [--json informe.json] [--codequality gl-code-quality-report.json]
```

Sale con 0 si el veredicto no llega a `--fail-on` (por defecto `red`), 1 si llega y 2 si hay un error. `--codequality` genera el formato de GitLab para que los hallazgos salgan en la merge request. `OMINOUS_OFFLINE=1` evita la consulta a OSV.dev.

## Docker

```bash
docker build -t ominous-security .
docker run --rm -p 127.0.0.1:8080:8080 -v ominous-clones:/data ominous-security
```

Publica el puerto solo en `127.0.0.1`. Los clones quedan en el volumen `ominous-clones`. La imagen incluye el escáner: `docker run --rm -v "$PWD:/src:ro" --entrypoint ominous-scan ominous-security /src`.

## Desarrollo y CI/CD (GitLab)

```bash
npm run lint        # sintaxis, 'use strict', JSON y caracteres invisibles
npm test            # 30 tests con node --test (Node 20+)
npm run scan:self   # la herramienta se analiza a sí misma
```

Los tests generan sus repos trampa en una carpeta temporal en cada ejecución (`test/helpers/fixtures.js`), así que el repo no contiene ficheros que VS Code, pytest o Claude Code pudieran ejecutar al abrirlo.

El pipeline (`.gitlab-ci.yml`) tiene estas fases:

| Fase | Jobs |
|---|---|
| lint | `lint` |
| test | tests en Node 20 y 24, `test:coverage` en Node 22 (JUnit y % de cobertura), `self-scan` (informe Code Quality en la MR), SAST y detección de secretos de GitLab, `npm-audit` |
| build | `package` (zip del código), `docker` (imagen en el Container Registry con prueba de humo; en `main`, en etiquetas y en MRs que tocan el Dockerfile o las dependencias) |
| scan | `container_scanning` de la imagen |
| deploy | `pages`: la interfaz en modo demo en GitLab Pages, para probarla desde el móvil |
| release | al crear una etiqueta `vX.Y.Z` que coincida con la versión de `package.json` |

Para publicar una versión: sube la versión en `package.json`, haz commit y `git tag v1.0.1 && git push --tags`.

## Estructura

```
server.js           servidor HTTP, descarga y clonado
bin/ominous-scan.js escáner por línea de comandos (CI)
lib/analyzer.js    recorrido del repo, chequeos estructurales, veredicto, arreglos automáticos
lib/rules.js       reglas de vulnerabilidades y amenazas
lib/decoder.js     ingeniería inversa de payloads codificados/cifrados
lib/deps.js        dependencias (OSV.dev) y typosquatting
lib/summary.js     resumen del diff de los arreglos (Claude o local)
lib/extra.js       autoejecutables, agentes de IA, lockfiles, señuelos, ZIP, homoglifos, submódulos
lib/history.js     historial de git
lib/worker.js      hilo de análisis con tiempo máximo
public/index.html  interfaz (sin servidor funciona en modo demo con datos simulados)
```
