# Ominous Security

[![CI](https://github.com/AlexDBdevops/ominous-security/actions/workflows/ci.yml/badge.svg)](https://github.com/AlexDBdevops/ominous-security/actions/workflows/ci.yml)
[![CodeQL](https://github.com/AlexDBdevops/ominous-security/actions/workflows/codeql.yml/badge.svg)](https://github.com/AlexDBdevops/ominous-security/actions/workflows/codeql.yml)

Herramienta web que analiza un repositorio de GitHub **antes de clonarlo**: vulnerabilidades del código, amenazas puestas a propósito por el autor y scripts ocultos o cifrados, que descifra sin ejecutarlos. Al final te deja clonarlo (con confirmación si algo no está en verde) y aplicar los arreglos automáticos, con el diff y un resumen de lo que ha cambiado.

**Demo sin instalar nada:** https://alexdbdevops.github.io/ominous-security/ (datos simulados).

- [Inicio rápido](#inicio-rápido)
- [Configuración](#configuración)
- [Despliegue](#despliegue)
- [Qué analiza](#qué-analiza)
- [Seguridad de la propia herramienta](#seguridad-de-la-propia-herramienta)
- [Escáner por línea de comandos](#escáner-por-línea-de-comandos)
- [Desarrollo y CI/CD](#desarrollo-y-cicd)
- [Solución de problemas](#solución-de-problemas)
- [Límites](#límites)

## Inicio rápido

**Con Docker** (recomendado: la app queda aislada en un contenedor endurecido):

```bash
git clone https://github.com/AlexDBdevops/ominous-security.git
cd ominous-security
scripts/local.sh            # Windows: .\scripts\local.ps1
```

El script construye la imagen, la arranca, espera a que responda y abre http://localhost:8080. Los clones quedan en `~/ominous-clones`. Necesitas Docker con el plugin `docker compose` (Docker Desktop ya lo trae).

**Sin Docker** (Node.js 18 o superior y git):

```bash
npm ci --omit=dev           # opcional: solo añade el SDK de Anthropic para los resúmenes por IA
npm start                   # o: scripts/local.sh node
```

Pega la URL del repo (`https://github.com/usuario/repo`, también vale con `/tree/rama`) y pulsa **Analizar**.

## Configuración

Todo se configura con variables de entorno. Con Docker, ponlas en un fichero `.env` (por ejemplo `ANTHROPIC_API_KEY=…` para la revisión con IA) junto a `compose.yaml` (Compose lo lee solo y está en `.gitignore`) o expórtalas antes de lanzar el script.

### Variables del script y de Docker Compose

| Variable | Por defecto | Para qué |
|---|---|---|
| `OMINOUS_PORT` | `8080` | Puerto en tu máquina |
| `OMINOUS_CLONES` | `~/ominous-clones` | Carpeta de tu máquina donde quedan los clones |
| `OMINOUS_LAN_IP` | se detecta | IP de tu equipo en la red local, solo para `scripts/local.sh lan` |

### Variables de la aplicación

| Variable | Por defecto | Para qué |
|---|---|---|
| `PORT` | `8080` | Puerto en el que escucha el servidor |
| `HOST` | `127.0.0.1` | Interfaz de red. En el contenedor es `0.0.0.0`, y Docker solo publica el puerto en `127.0.0.1` |
| `CLONE_DIR` | `~/ominous-clones` | Carpeta de clones. Los clones solo pueden ir dentro de ella |
| `GITHUB_TOKEN` | — | Token de GitHub de solo lectura. Sube el límite de la API de 60 a 5000 peticiones por hora (metadatos, releases y reputación del autor) |
| `ANTHROPIC_API_KEY` | — | Activa la revisión con IA y el resumen por IA del diff. Sin ella se genera un resumen local y la revisión con IA queda desactivada |
| `OMINOUS_MODEL` | `claude-opus-5-5` | Modelo de Claude |
| `OMINOUS_AI_EFFORT` | `high` | Esfuerzo de la revisión con IA (`low`, `medium`, `high`, `xhigh`, `max`): más alto, más profunda y más cara |
| `OMINOUS_AI_MAX_CHARS` | `160000` | Máximo de caracteres del repo que se envían a Claude por revisión |
| `ALLOWED_HOSTS` | — | Nombres extra con los que se puede abrir la app (`miservidor:8080,192.168.1.20:8080`). Si alguno no es de esta máquina, `OMINOUS_TOKEN` pasa a ser obligatorio |
| `OMINOUS_TOKEN` | — | Token de acceso (mínimo 24 caracteres). Genera uno con `openssl rand -hex 24` |
| `ALLOW_ANY_HOST` | — | `1` acepta cualquier nombre de host. Desaconsejado; también exige token |
| `ALLOW_ANY_DEST` | — | `1` permite clonar fuera de `CLONE_DIR`. Solo funciona si la app no está expuesta |
| `HISTORY_COMMITS` | `300` | Commits del historial que se revisan |
| `ANALYSIS_TIMEOUT_MS` | `300000` | Tiempo máximo de un análisis |
| `MAX_REPO_MB` | `1024` | Tamaño máximo del repo, según GitHub |
| `MAX_CONCURRENT` | `2` | Análisis simultáneos |
| `RATE_LIMIT` | `30` | Análisis por IP cada 10 minutos |
| `OMINOUS_OFFLINE` | — | `1` no consulta OSV.dev (útil en tests o sin conexión) |

## Despliegue

### En tu equipo con Docker

```bash
scripts/local.sh            # construir y arrancar
scripts/local.sh logs       # ver los logs
scripts/local.sh down       # parar
scripts/local.sh rebuild    # reconstruir sin caché (por ejemplo, tras actualizar)
```

El contenedor (`compose.yaml`) corre con tu usuario, con el sistema de ficheros en solo lectura y sin capacidades de Linux, no puede escalar privilegios y tiene límites de memoria (2 GB), CPU (2) y procesos (256). Solo escribe en la carpeta de clones y en `/tmp`.

Para usar la imagen ya publicada en lugar de construirla:

```bash
docker run -d --name ominous -p 127.0.0.1:8080:8080 \
  -v "$HOME/ominous-clones:/data" --user "$(id -u):$(id -g)" \
  --read-only --tmpfs /tmp:size=2g --cap-drop ALL --security-opt no-new-privileges \
  ghcr.io/alexdbdevops/ominous-security:latest
```

### En tu equipo sin Docker

`scripts/local.sh node` comprueba que tienes Node.js 18+ y git, instala el SDK opcional y arranca el servidor en `127.0.0.1`.

### Desde el móvil, en tu red local

```bash
scripts/local.sh lan
```

Detecta tu IP, genera un token (lo guarda en `.ominous-token`) y te da una URL como `http://192.168.1.20:8080/?token=…`. Ábrela en el móvil una vez: el token se guarda en una cookie y la URL desaparece. Va por HTTP sin cifrar, así que úsalo solo en una red de confianza y vuelve a `scripts/local.sh up` al terminar.

### En un servidor

Si la publicas en internet, ponla detrás de un proxy con HTTPS y con token. Ejemplo con [Caddy](https://caddyserver.com) en el mismo servidor:

```bash
# .env
OMINOUS_TOKEN=<openssl rand -hex 24>
```

```yaml
# compose.override.yaml
services:
  app:
    environment:
      ALLOWED_HOSTS: "ominous.tudominio.com"
      OMINOUS_TOKEN: ${OMINOUS_TOKEN:?}
```

```
# Caddyfile
ominous.tudominio.com {
  reverse_proxy 127.0.0.1:8080
}
```

Entra una vez en `https://ominous.tudominio.com/?token=<tu token>`. Caddy obtiene el certificado y la cookie se marca como `Secure`. Ten en cuenta que los clones se guardan en el disco del servidor, no en el tuyo.

### Demo en GitHub Pages

En cada push a `main`, el job `pages` publica la interfaz en modo demo, sin servidor detrás. Para activarlo la primera vez ve a *Settings > Pages > Build and deployment > Source* y elige *GitHub Actions*.

## Qué analiza

El repo se descarga en una carpeta temporal con git endurecido (sin hooks, sin submódulos, sin LFS y sin protocolos locales) y **nunca se ejecuta nada de él**. Al terminar se borra.

**Vulnerabilidades del código.** Hay unas 100 reglas para JS/TS, Python, PHP, Go, Java, Ruby, Rust, C/C++, C#, Swift/Android, shell, Docker, Compose, Kubernetes, Terraform y GitHub Actions. También busca secretos de unos 20 proveedores y consulta en OSV.dev las dependencias con vulnerabilidades conocidas (npm, PyPI y Go). Cada hallazgo indica si **se puede arreglar** (con la solución) o **no** (con el motivo). Los arreglos *automáticos* se aplican si marcas la casilla al clonar. Lo que está en tests, ejemplos o documentación se rebaja a informativo.

**Amenazas deliberadas:**

- **Instalación y apertura:** scripts `postinstall`, `setup.py` y build backends, tareas de VS Code que se lanzan al abrir la carpeta, devcontainers, git hooks y ficheros que se ejecutan solos (`conftest.py`, `.pth`, `sitecustomize.py`, `build.rs`, Gradle/Maven, `.envrc`, pre-commit, configs de webpack/jest/eslint). También ajustes de VS Code que apuntan a ejecutables, y hooks de Claude Code y servidores MCP del proyecto.
- **Malware clásico:** `curl | sh`, reverse shells, mineros, robo de credenciales (navegador, Discord, carteras, SSH, AWS), webhooks de exfiltración, persistencia, desactivación del antivirus, keyloggers, clippers de criptomonedas, diálogos falsos de contraseña, puertas traseras SSH, comandos destructivos y borrado de rastros.
- **Ocultación:** Trojan Source (Unicode bidi), caracteres invisibles, homoglifos, código escondido tras cientos de espacios, binarios disfrazados de imagen, **imágenes con un ejecutable o código pegado al final**, librerías de esteganografía y código que ejecuta lo que lee de una imagen.
- **Cadena de suministro:** lockfiles que descargan de servidores no oficiales, registros alternativos (dependency confusion), dependencias catalogadas como malware en OSV, typosquatting, paquetes que **instalan comandos con nombre de herramientas del sistema** (`git`, `npm`, `sudo`…), `yarnPath` y wrappers de Gradle modificados.
- **CI y contenedores:** workflows que vuelcan todos los secretos (`toJSON(secrets)`), `pull_request_target`, inyección en Actions, acciones de terceros sin fijar, runners propios, contenedores privilegiados, en red o procesos del host, con capacidades peligrosas, que montan `/`, `/etc` o tu carpeta personal o el socket de Docker, y Dockerfiles que corren como root.
- **Agentes de IA:** instrucciones peligrosas en `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, etc.
- **Señuelos:** READMEs que piden descargar un zip con contraseña, ZIP cifrados o con ejecutables y dobles extensiones (`factura.pdf.exe`).
- **Historial de git:** revisa las líneas borradas de los últimos 300 commits en busca de secretos y código malicioso que se quitó pero sigue en el repo.
- **Submódulos y releases:** analiza hasta 8 submódulos en el commit exacto que fija el repo y avisa de binarios publicados en releases.
- **Reputación:** estrellas, antigüedad del repo y de la cuenta, licencia, archivado, cuentas nuevas con estrellas infladas, **repos renombrados o transferidos (repojacking)** y la puntuación **OpenSSF Scorecard** del proyecto.

**Ingeniería inversa de scripts ocultos.** Pela capas de base64, hex, zlib/gzip/deflate, `String.fromCharCode`, cadenas invertidas, XOR de un byte (por fuerza bruta) y **Fernet (AES) cuando la clave está en el repo**, y vuelve a analizar el resultado. Si la clave no está en el repo, lo marca como no descifrable.

**Revisión con IA (opcional).** Las reglas encuentran patrones conocidos; con el botón **Revisar con Claude** se envían a la API de Anthropic los ficheros de más riesgo (los que se ejecutan al instalar o abrir el proyecto, los que tienen avisos, los puntos de entrada y el código descifrado, hasta 40 ficheros y `OMINOUS_AI_MAX_CHARS` caracteres) junto con el árbol de ficheros y los hallazgos de las reglas. Claude busca lo que no tiene firma (lógica maliciosa nueva, técnicas para esquivar sandboxes, fallos de autorización, código que no encaja con lo que el proyecto dice ser) y señala posibles falsos positivos. Reglas de seguridad de esta función:

- Solo se envía algo si pulsas el botón, y la app te dice antes cuántos ficheros y cuánto texto.
- El contenido del repo va marcado como datos no fiables: si contiene instrucciones dirigidas a la IA, eso se reporta como amenaza.
- La IA **solo puede añadir avisos**. Sus "falsos positivos" se muestran como opinión y nunca rebajan el veredicto; si encuentra algo grave, clonar exige la casilla de confirmación aunque las reglas den verde (también lo comprueba el servidor).
- La respuesta se valida contra un esquema JSON estricto antes de mostrarse.

Una revisión grande envía unos 50.000 tokens; con `claude-opus-5-5` a esfuerzo `high` cuesta del orden de 0,20 a 0,50 USD (estimación). Baja `OMINOUS_AI_EFFORT` u `OMINOUS_AI_MAX_CHARS` para abaratarla.

**Cobertura.** Cada análisis muestra qué se ha revisado por completo, qué parcialmente y qué no.

**Clonar.** El botón está al final. Si el resultado no está en verde exige marcar la casilla de confirmación, y el servidor también lo comprueba. El clon se fija al commit exacto que se analizó. Si aplicas arreglos verás el diff y un resumen de cada cambio, por qué es más seguro y qué podría romper, y podrás deshacerlos con un botón. El resumen lo escribe Claude si hay `ANTHROPIC_API_KEY`; en ese caso, y solo en ese, el diff se envía a la API de Anthropic.

## Seguridad de la propia herramienta

- **Red:** por defecto solo escucha en `127.0.0.1` y rechaza cualquier `Host` que no sea de esta máquina (protección contra DNS rebinding) y cualquier POST con un `Origin` ajeno (CSRF). Las peticiones tienen que ser JSON y de 64 KB como mucho.
- **Exposición:** si se abre a otros nombres (`ALLOWED_HOSTS`/`ALLOW_ANY_HOST`) no arranca sin `OMINOUS_TOKEN`. El token se compara en tiempo constante y se guarda en una cookie `HttpOnly`, `SameSite=Strict` (y `Secure` detrás de HTTPS).
- **Disco:** los clones solo pueden ir dentro de `CLONE_DIR`, también si hay enlaces simbólicos por medio. Así se evita clonar en carpetas que se ejecutan solas, como `~/.vim/pack/*/start` o `~/.config/autostart`.
- **Abuso:** límite de análisis por IP, de análisis simultáneos y de tamaño del repo. Cada análisis corre en un hilo aparte con tiempo máximo, para que un fichero diseñado para bloquear analizadores (ReDoS) no deje colgada la app.
- **Navegador:** cabeceras `Content-Security-Policy` estricta, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy` y `Permissions-Policy`.
- **Procesos:** URLs validadas de forma estricta, git sin shell y endurecido, y errores internos que no exponen detalles.
- **Proyecto:** CI con CodeQL, autoescaneo, `npm audit`, Trivy sobre la imagen y Dependabot, usando solo acciones oficiales de GitHub.

## Escáner por línea de comandos

Analiza una carpeta local sin servidor, por ejemplo en el CI de otros proyectos:

```bash
node bin/ominous-scan.js <carpeta> [--exclude ruta1,carpeta/] [--fail-on red|yellow|never] \
     [--json informe.json] [--sarif ominous.sarif] [--codequality gl-code-quality-report.json]
scripts/local.sh scan ~/proyectos/algo   # lo mismo, dentro del contenedor, sin red y en solo lectura
```

Sale con 0 si el veredicto no llega a `--fail-on` (por defecto `red`), con 1 si llega y con 2 si hay un error. `--sarif` genera el formato de GitHub code scanning y `--codequality` el de GitLab.

En GitHub Actions:

```yaml
- run: |
    docker run --rm -v "$PWD:/src:ro" --entrypoint ominous-scan \
      ghcr.io/alexdbdevops/ominous-security:latest /src --fail-on red
```

## Desarrollo y CI/CD

```bash
npm run lint        # sintaxis, 'use strict', JSON y caracteres invisibles o bidi
npm test            # tests con node --test (Node 20+)
npm run scan:self   # la herramienta se analiza a sí misma
```

Los tests generan sus repos trampa en una carpeta temporal en cada ejecución (`test/helpers/fixtures.js`). Así el repo no contiene ficheros que VS Code, pytest o Claude Code pudieran ejecutar al abrirlo.

`.github/workflows/ci.yml` corre en cada push y pull request:

| Job | Qué hace |
|---|---|
| `lint` | `npm run lint` |
| `test` | tests en Node 20, 22 y 24; en 22 con cobertura (resumen del job) y JUnit |
| `self-scan` | la herramienta se analiza a sí misma; en repos públicos los hallazgos salen en *Security > Code scanning* |
| `audit` | `npm audit` |
| `docker` | imagen con prueba de humo y escaneo Trivy; desde `main` y etiquetas se publica en `ghcr.io/alexdbdevops/ominous-security` |
| `package` | zip del código como artefacto |
| `pages` | demo en GitHub Pages |
| `release` | release de GitHub al subir una etiqueta `vX.Y.Z` que coincida con `package.json` |

`codeql.yml` pasa CodeQL cada semana y en cada PR, y Dependabot vigila npm, las acciones y la imagen base.

Para publicar una versión, sube la versión en `package.json`, haz commit y ejecuta `git tag v1.0.1 && git push --tags`.

Al autoescanearse se excluyen `lib/rules.js`, `lib/decoder.js`, `lib/extra.js`, la demo y este README: contienen las firmas que busca, igual que la base de firmas de un antivirus.

## Solución de problemas

| Síntoma | Causa y solución |
|---|---|
| `Host no permitido` (403) | Abres la app con un nombre o puerto distinto del configurado. Usa `http://localhost:<OMINOUS_PORT>` o añade el nombre a `ALLOWED_HOSTS` |
| No arranca: `no tiene token` | Has configurado `ALLOWED_HOSTS` con un nombre externo. Define `OMINOUS_TOKEN` (24+ caracteres) |
| `Falta el token de acceso` (401) | Abre una vez `/?token=<tu token>` para guardar la cookie |
| `Permission denied` al clonar con Docker | La carpeta de clones no es de tu usuario. Ejecuta `sudo chown -R "$(id -u):$(id -g)" ~/ominous-clones` |
| `El destino tiene que estar dentro de…` | El campo de destino admite solo un nombre de carpeta, dentro de `CLONE_DIR` |
| Reputación, Releases o Scorecard en gris | La API de GitHub ha alcanzado el límite (define `GITHUB_TOKEN`) o el proyecto no tiene Scorecard publicado |
| `Dependencias (OSV.dev): no se pudo consultar` | Sin conexión con api.osv.dev o `OMINOUS_OFFLINE=1` |
| El puerto 8080 está ocupado | `OMINOUS_PORT=9090 scripts/local.sh` |

## Límites

Es análisis estático por patrones: reduce mucho el riesgo, pero no es una garantía. Un atacante decidido puede esquivar reglas concretas o descargar el payload real en tiempo de ejecución desde un servidor (eso se marca, pero no se puede ver qué descargará). Analiza hasta 8000 ficheros de 1,5 MB como máximo. Los binarios de las releases y los ficheros de Git LFS no se descargan.

## Estructura

```
server.js            servidor HTTP, descarga, clonado, token y límites
bin/ominous-scan.js  escáner por línea de comandos (JSON, SARIF, Code Quality)
lib/analyzer.js      recorrido del repo, chequeos estructurales, veredicto, arreglos automáticos
lib/rules.js         reglas de vulnerabilidades y amenazas
lib/decoder.js       ingeniería inversa de payloads codificados o cifrados
lib/deps.js          dependencias (OSV.dev) y typosquatting
lib/extra.js         autoejecutables, agentes de IA, lockfiles, señuelos, ZIP, imágenes, homoglifos
lib/history.js       historial de git
lib/summary.js       resumen del diff de los arreglos (Claude o local)
lib/ai.js            revisión con IA: selección de ficheros, prompt, esquema y validación
lib/worker.js        hilo de análisis con tiempo máximo
public/index.html    interfaz (sin servidor funciona en modo demo)
Dockerfile           imagen (usuario sin privilegios, tini, healthcheck)
compose.yaml         despliegue local endurecido; compose.lan.yaml lo abre a tu red con token
scripts/local.sh     construir y arrancar en local (local.ps1 en Windows)
test/                tests con node --test
```

## Licencia

[MIT](LICENSE)
