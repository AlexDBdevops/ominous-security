# Ominous Security

[![CI](https://github.com/AlexDBdevops/ominous-security/actions/workflows/ci.yml/badge.svg)](https://github.com/AlexDBdevops/ominous-security/actions/workflows/ci.yml)
[![CodeQL](https://github.com/AlexDBdevops/ominous-security/actions/workflows/codeql.yml/badge.svg)](https://github.com/AlexDBdevops/ominous-security/actions/workflows/codeql.yml)

Herramienta web que analiza un repositorio de GitHub **antes de clonarlo**: vulnerabilidades del código, amenazas puestas a propósito por el autor y scripts ocultos o cifrados, que descifra sin ejecutarlos. Al final te deja clonarlo (con confirmación si algo no está en verde) y aplicar los arreglos automáticos, con el diff y un resumen de lo que ha cambiado.

**Sin instalar nada:** https://alexdbdevops.github.io/ominous-security/ (análisis real en el navegador; los tres ejemplos usan datos simulados). Ver [Versión web](#versión-web).

- [Inicio rápido](#inicio-rápido)
- [Configuración](#configuración)
- [Despliegue](#despliegue)
- [Qué analiza](#qué-analiza)
- [Vigilancia de tus clones](#vigilancia-de-tus-clones)
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

Todo se configura con variables de entorno. Con Docker, ponlas en un fichero `.env` (por ejemplo `OMINOUS_PORT=9090`) junto a `compose.yaml` (Compose lo lee solo y está en `.gitignore`) o expórtalas antes de lanzar el script.

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
| `ANTHROPIC_API_KEY` | — | Opcional. Clave de la API para la revisión con IA y el resumen del diff. También se puede escribir en la ventana **Conectar Claude** o usar tu cuenta con Claude Code (ver [Conectar Claude](#conectar-claude)) |
| `OMINOUS_AI_METHOD` | — | `claude-code` para arrancar ya conectado con tu cuenta a través de Claude Code. Si no, se usa la clave si existe |
| `OMINOUS_CLAUDE_BIN` | `claude` | Ruta del ejecutable de Claude Code |
| `OMINOUS_CLAUDE_MODEL` | el de Claude Code | Modelo para la revisión con Claude Code (`sonnet`, `opus`…) |
| `OMINOUS_CLAUDE_TIMEOUT` | `600000` | Tiempo máximo de una revisión con Claude Code, en ms |
| `OMINOUS_MODEL` | `claude-opus-5-5` | Modelo de Claude con clave de la API |
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
| `OMINOUS_OFFLINE` | — | `1` no consulta ningún servicio externo: OSV.dev, deps.dev, EPSS ni los registros de npm y PyPI (útil en tests o sin conexión) |
| `OMINOUS_EXTERNAL` | — | `0` no usa Gitleaks, Semgrep, Trivy ni CodeQL aunque estén instalados (ver [Herramientas externas](#herramientas-externas-opcionales)) |
| `OMINOUS_GITLEAKS_BIN`, `OMINOUS_SEMGREP_BIN`, `OMINOUS_TRIVY_BIN`, `OMINOUS_CODEQL_BIN` | el del `PATH` | Ruta de cada herramienta externa |
| `OMINOUS_SEMGREP_CONFIG` | `p/default` | Reglas de Semgrep, separadas por comas: conjuntos del registro (`p/default,p/owasp-top-ten`) o ficheros y carpetas locales, como un clon de [semgrep-rules](https://github.com/semgrep/semgrep-rules) (así no conecta con semgrep.dev) |
| `OMINOUS_EXTERNAL_TIMEOUT_MS` | `240000` | Tiempo máximo de Gitleaks, Semgrep y Trivy |
| `OMINOUS_CODEQL_TIMEOUT_MS` | `480000` | Tiempo máximo de CodeQL por lenguaje |
| `OMINOUS_WATCH` | — | `0` desactiva la [vigilancia de tus clones](#vigilancia-de-tus-clones) |
| `OMINOUS_WATCH_HOURS` | `24` | Cada cuántas horas se comprueban los clones |

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

### Versión web en GitHub Pages

La misma página se publica en GitHub Pages en su edición **web**: analiza repos públicos de verdad desde el navegador de quien la visita, sin servidor y sin IA (ver [Versión web](#versión-web)). No hace falta infraestructura propia ni secretos: en cada push a `main`, el job `pages` genera `dist/` con `npm run build:site` y lo publica con las acciones oficiales `upload-pages-artifact` y `deploy-pages`.

GitHub Pages no deja poner cabeceras, así que la CSP va en un `<meta>` al principio de la página. Autoriza cada script por su hash, `analyzer.js` del propio dominio y conexiones solo a `api.github.com`, `raw.githubusercontent.com`, `api.osv.dev`, `api.securityscorecards.dev`, `api.deps.dev`, `api.first.org` (EPSS), `registry.npmjs.org`, `pypi.org` y `files.pythonhosted.org`. Todas son consultas de solo lectura a datos públicos, y el token de GitHub opcional solo va a `api.github.com`. Un `<meta>` no admite `frame-ancestors`, así que la página se queda oculta si otro sitio la mete en un marco (contra el clickjacking). HTTPS y HSTS los pone `github.io`.

Configuración, una sola vez: en GitHub, *Settings > Pages > Build and deployment > Source*: **GitHub Actions**. La URL queda en `https://alexdbdevops.github.io/ominous-security/` y sale en el resumen del job.

Para probarla en local: `npm run build:site && npx serve dist`.

## Herramientas externas (opcionales)

En el servidor local, si tienes instaladas estas herramientas de código abierto, se pasan también sobre el clon temporal y sus hallazgos se suman a los de las reglas propias, cada uno con la explicación de la propia herramienta (regla, CWE y enlaces):

| Herramienta | Qué añade | Instalar |
|---|---|---|
| [Gitleaks](https://github.com/gitleaks/gitleaks) | más de un centenar de reglas de secretos, también en el historial descargado | `brew install gitleaks` |
| [Semgrep](https://github.com/semgrep/semgrep) | el conjunto `p/default`: cientos de reglas de seguridad en más de 30 lenguajes. Descarga las reglas de semgrep.dev, con las métricas desactivadas | `pipx install semgrep` |
| [Trivy](https://github.com/aquasecurity/trivy) | secretos y errores de configuración en Dockerfile, Kubernetes, Terraform, CloudFormation y Helm | `brew install trivy` |
| [CodeQL](https://github.com/github/codeql-cli-binaries) | **recorridos de datos**: sigue cada valor desde donde entra (una petición, un argumento, un fichero) hasta donde hace daño (`exec`, SQL, `eval`…), también entre funciones y ficheros. Usa el conjunto `security-extended` | el *bundle* de [codeql-action](https://github.com/github/codeql-action/releases) (trae las consultas) |

Ninguna ejecuta código del repo: solo leen ficheros. Se lanzan sin shell, con tiempo máximo y un entorno mínimo, en paralelo. Si una no está instalada, no aparece; si falla, sale como "no revisado". La imagen de Docker no las incluye. No están en la versión web porque no se pueden ejecutar en un navegador.

**Sobre CodeQL:**

- Solo analiza JavaScript/TypeScript, Python y Ruby. Java, Kotlin, C#, C/C++, Go y Swift suelen necesitar compilar el proyecto, y compilar ejecuta código del repo (plugins de Maven o Gradle, scripts de build). Eso rompería la regla de no ejecutar nada.
- Es lento: cada lenguaje tarda de medio minuto a varios minutos, y el *bundle* ocupa más de 1 GB.
- Cada hallazgo muestra en su ficha **el recorrido del dato**, paso a paso, con fichero y línea. Si en algún paso se valida o se escapa el dato, puede ser un falso positivo.
- Su licencia permite usarlo gratis en código open source y en investigación. Revisa sus [condiciones](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md) antes de usarlo con código privado.

**Sobre Semgrep:** la versión gratuita también sigue datos, pero solo dentro de cada función. Sus reglas se descargan al usarlas y su licencia no permite copiarlas dentro de otra herramienta, así que Ominous no las incluye: usa las que tengas instaladas o descargadas.

## Versión web

Una sola rama y una sola página con tres ediciones. Solo cambia una línea (`const EDITION`) y la CSP, que genera `lib/page.js`:

| Edición | Dónde | Qué hace |
|---|---|---|
| `local` | servidor local (`npm start`, Docker) | todo: clon aislado, historial de git, submódulos, clonado con arreglos y revisión con Claude (tu cuenta Pro/Max o una clave) |
| `web` | GitHub Pages | análisis real en el navegador, sin IA |
| `web-ai` | artefacto de claude.ai | lo mismo que `web` más la revisión con Claude usando la cuenta de claude.ai de quien lo abre |

En las ediciones web, `public/analyzer.js` (el mismo analizador de `lib/`, empaquetado con `npm run build:web`) corre en un Web Worker:

1. Pide los metadatos del repo y el commit de la rama a la API de GitHub, y la lista de ficheros de ese commit.
2. Descarga cada fichero desde `raw.githubusercontent.com` en ese commit exacto, a la memoria de la pestaña. Nada se escribe en disco ni se ejecuta.
3. Pasa las mismas reglas que el servidor (los tests comprueban que los hallazgos son idénticos) y consulta OSV.dev, OpenSSF Scorecard, deps.dev, EPSS y los registros de npm y PyPI (ver [Más allá del repo](#más-allá-del-repo)).
4. Si el análisis pasa de 5 minutos, la página corta el worker (protege de ficheros diseñados para colgar analizadores).

Para clonar, la página da el comando que deja el clon en el commit analizado y, si se pide, descarga un parche con los arreglos automáticos para aplicarlo con `git apply`.

Cada hallazgo lleva una ficha **¿Qué es esto?** sin IA: el tipo de fallo (con su CWE), por qué importa, qué comprobar y, en las dependencias, los avisos publicados en OSV.dev (identificadores CVE/GHSA, resumen, versión corregida y enlaces).

Si GitHub no encuentra el repo, la página explica los motivos posibles: la cuenta no existe (mal escrita, borrada o suspendida) o el repo no es público (mal escrito, privado, borrado, retirado por GitHub o renombrado sin redirección). También avisa de rama inexistente, repo vacío, bloqueo legal o por GitHub, límite de consultas y falta de conexión.

Límites de la versión web frente al servidor local:

- Sin historial de git ni submódulos (se marcan como no revisados).
- Sin iniciar sesión, la API de GitHub permite 60 consultas por hora por IP. Cada análisis usa unas 5. Los ficheros desde `raw.githubusercontent.com` no cuentan. Con un token de GitHub opcional (fine-grained y sin permisos) sube a 5000: solo se envía a `api.github.com`, vive en la memoria del worker durante el análisis y nunca se guarda.
- Hasta 3000 ficheros, 2 MB por fichero y 60 MB en total.
- Si algún servicio (OSV.dev, Scorecard, deps.dev, EPSS, npm o PyPI) no responde al navegador, sale como "no revisado" en lugar de fallar.

## Qué analiza

El repo se descarga en una carpeta temporal con git endurecido (sin hooks, sin submódulos, sin LFS y sin protocolos locales) y **nunca se ejecuta nada de él**. Al terminar se borra.

**Vulnerabilidades del código.** Hay unas 115 reglas para JS/TS, Python, PHP, Go, Java, Ruby, Rust, C/C++, C#, Swift/Android, shell, Docker, Compose, Kubernetes, Terraform y GitHub Actions. También busca secretos de unos 20 proveedores y consulta en OSV.dev las dependencias con vulnerabilidades conocidas: npm (package.json, package-lock, yarn.lock), PyPI (requirements, poetry.lock, Pipfile.lock), Go, crates.io (Cargo.lock), RubyGems (Gemfile.lock), Packagist (composer.lock) y Maven (pom.xml, build.gradle). Cada hallazgo indica si **se puede arreglar** (con la solución) o **no** (con el motivo). Los arreglos *automáticos* se aplican si marcas la casilla al clonar. Lo que está en tests, ejemplos o documentación se rebaja a informativo.

**Amenazas deliberadas:**

- **Instalación y apertura:** scripts `postinstall`, `setup.py` y build backends, tareas de VS Code que se lanzan al abrir la carpeta, devcontainers, git hooks y ficheros que se ejecutan solos (`conftest.py`, `.pth`, `sitecustomize.py`, `build.rs`, Gradle/Maven, `.envrc`, pre-commit, configs de webpack/jest/eslint). También ajustes de VS Code que apuntan a ejecutables, y hooks de Claude Code y servidores MCP del proyecto.
- **Malware clásico:** `curl | sh`, reverse shells, mineros, robo de credenciales (navegador, Discord, carteras, SSH, AWS), webhooks de exfiltración, persistencia, desactivación del antivirus, keyloggers, clippers de criptomonedas, diálogos falsos de contraseña, puertas traseras SSH, comandos destructivos y borrado de rastros.
- **Ocultación:** Trojan Source (Unicode bidi), caracteres invisibles, homoglifos, código escondido tras cientos de espacios, binarios disfrazados de imagen, **imágenes con un ejecutable o código pegado al final**, librerías de esteganografía y código que ejecuta lo que lee de una imagen.
- **Cadena de suministro:** lockfiles que descargan de servidores no oficiales, registros alternativos (dependency confusion), dependencias catalogadas como malware en OSV, typosquatting, paquetes que **instalan comandos con nombre de herramientas del sistema** (`git`, `npm`, `sudo`…), `yarnPath`, wrappers de Gradle modificados y la lista de dependencias que ejecutan scripts al instalarse (según `package-lock.json`).
- **CI y contenedores:** workflows que vuelcan todos los secretos (`toJSON(secrets)`), `pull_request_target`, inyección en Actions, acciones de terceros sin fijar, runners propios, contenedores privilegiados, en red o procesos del host, con capacidades peligrosas, que montan `/`, `/etc` o tu carpeta personal o el socket de Docker, y Dockerfiles que corren como root.
- **Agentes de IA:** instrucciones peligrosas en `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, etc.
- **Señuelos:** READMEs que piden descargar un zip con contraseña, ZIP cifrados o con ejecutables y dobles extensiones (`factura.pdf.exe`).
- **Historial de git:** revisa las líneas borradas de los últimos 300 commits en busca de secretos y código malicioso que se quitó pero sigue en el repo.
- **Submódulos y releases:** analiza hasta 8 submódulos en el commit exacto que fija el repo y avisa de binarios publicados en releases.
- **Reputación:** estrellas, antigüedad del repo y de la cuenta, licencia, archivado, cuentas nuevas con estrellas infladas, **repos renombrados o transferidos (repojacking)** y la puntuación **OpenSSF Scorecard** del proyecto.

**Ingeniería inversa de scripts ocultos.** Pela capas de base64, hex, zlib/gzip/deflate, `String.fromCharCode`, cadenas invertidas, XOR de un byte (por fuerza bruta) y **Fernet (AES) cuando la clave está en el repo**, y vuelve a analizar el resultado. Si la clave no está en el repo, lo marca como no descifrable.

**Revisión con IA (opcional).** Las reglas encuentran patrones conocidos; con Claude conectado (ver [Conectar Claude](#conectar-claude)) y el botón **Revisar con Claude** se envían a Claude los ficheros de más riesgo (los que se ejecutan al instalar o abrir el proyecto, los que tienen avisos, los puntos de entrada y el código descifrado, hasta 40 ficheros y `OMINOUS_AI_MAX_CHARS` caracteres) junto con el árbol de ficheros y los hallazgos de las reglas. Claude busca lo que no tiene firma (lógica maliciosa nueva, técnicas para esquivar sandboxes, fallos de autorización, código que no encaja con lo que el proyecto dice ser) y señala posibles falsos positivos. Reglas de seguridad de esta función:

- Solo se envía algo si pulsas el botón, y la app te dice antes cuántos ficheros y cuánto texto.
- El contenido del repo va marcado como datos no fiables: si contiene instrucciones dirigidas a la IA, eso se reporta como amenaza.
- La IA **solo puede añadir avisos**. Sus "falsos positivos" se muestran como opinión y nunca rebajan el veredicto; si encuentra algo grave, clonar exige la casilla de confirmación aunque las reglas den verde (también lo comprueba el servidor).
- La respuesta se valida contra un esquema JSON estricto antes de mostrarse.

### Conectar Claude

El botón **Conectar Claude** de la cabecera abre una ventana para elegir con qué cuenta se hace la revisión. Al conectar, la app comprueba la conexión y muestra una marca verde con el método, el tipo de cuenta y la hora de la comprobación. El botón de la cabecera pasa a **Claude conectado**.

| Opción | Coste | Cómo funciona |
|---|---|---|
| **Mi cuenta de Claude (Pro o Max)** | Sin coste extra: gasta el uso de tu plan | Usa el Claude Code instalado en el equipo donde corre la app, con tu sesión iniciada (`claude` una vez para iniciar sesión). La app nunca lee tus credenciales: ejecuta `claude -p` sin herramientas (`--tools ""`), sin MCP, en modo seguro (sin CLAUDE.md, hooks ni plugins), sin guardar la sesión, en una carpeta vacía y sin `ANTHROPIC_API_KEY` en su entorno. El contenido del repo entra por la entrada estándar, nunca como argumento. No está disponible dentro de Docker; usa `scripts/local.sh node` |
| **Clave de la API de Anthropic** | Pago por uso, aparte de Pro o Max | Una suscripción Pro no paga la API: la clave se factura en console.anthropic.com. Una revisión grande envía unos 50.000 tokens; con `claude-opus-5-5` a esfuerzo `high` cuesta del orden de 0,20 a 0,50 USD (estimación). Baja `OMINOUS_AI_EFFORT` u `OMINOUS_AI_MAX_CHARS` para abaratarla. La clave puede venir de `ANTHROPIC_API_KEY` o escribirse en la ventana |
| **Tu cuenta de claude.ai** (solo la demo) | Sin coste extra | Al abrir la demo como artefacto en claude.ai, Claude revisa de verdad los hallazgos simulados del ejemplo con la cuenta de quien la abre, tras pedir permiso |

Seguridad de la ventana:

- La clave escrita en la ventana vive solo en la memoria del servidor: no se guarda en disco, no se escribe en el log y nunca se devuelve al navegador (solo sus primeros y últimos caracteres).
- Si la app está expuesta a la red, la clave solo se acepta a través de HTTPS (cabecera `X-Forwarded-Proto: https` del proxy); en otro caso, usa `ANTHROPIC_API_KEY`.
- La ventana usa el mismo token, la misma protección CSRF y el mismo límite de peticiones que el resto de la API.
- Comprobar una clave consulta el modelo en la API y no gasta tokens. Comprobar Claude Code ejecuta `claude --version` y `claude auth status`, que no gastan uso.

**Cobertura.** Cada análisis muestra qué se ha revisado por completo, qué parcialmente y qué no.

**Clonar.** El botón está al final. Si el resultado no está en verde exige marcar la casilla de confirmación, y el servidor también lo comprueba. El clon se fija al commit exacto que se analizó. Si aplicas arreglos verás el diff y un resumen de cada cambio, por qué es más seguro y qué podría romper, y podrás deshacerlos con un botón. El resumen lo escribe Claude si está conectado; en ese caso, y solo en ese, el diff se envía a Claude.

### Más allá del repo

Lo que no está en el código que descargas, pero te afecta igual:

- **El paquete publicado.** `npm install` y `pip install` no descargan el repo: descargan lo que el autor (o quien le haya robado la cuenta) subió al registro. Si el repo publica un paquete en npm o PyPI que enlaza a ese mismo repo, se descarga la última versión (sin instalarla) y se compara con GitHub: scripts de instalación distintos, ficheros `.pth` o `setup.py` que no están en el repo, y las reglas de amenazas sobre cada fichero que no coincide.
- **Vulnerabilidades del propio proyecto.** Se consulta en OSV.dev el commit analizado y el paquete del proyecto (nombre y versión).
- **Dependencias indirectas sin lockfile.** Si un `package.json` no trae `package-lock.json` ni `yarn.lock`, solo se conocen las dependencias directas, pero `npm install` instalaría también las de esas. [deps.dev](https://deps.dev) resuelve el árbol que saldría hoy (la versión más alta que cumple cada rango) y todo se consulta en OSV.dev. De momento solo npm.
- **¿Se está explotando?** Las CVE de cada aviso se cruzan con el [catálogo KEV de CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (vulnerabilidades que se están explotando ya: sube la gravedad a alta como mínimo) y con [EPSS](https://www.first.org/epss/) (probabilidad de explotación en los próximos 30 días). Solo pueden subir la gravedad, nunca bajarla.

## Vigilancia de tus clones

En el servidor local, cada repo que clonas desde la app queda apuntado con los avisos que ya tenían sus dependencias. Al arrancar y luego cada 24 horas (`OMINOUS_WATCH_HOURS`), o con el botón **Comprobar ahora**, se vuelven a leer sus ficheros de dependencias, se consultan en OSV.dev y aparece en la sección **Vigilancia de tus clones** cualquier vulnerabilidad publicada después del clon, una sola vez y marcada si ya se está explotando.

Solo se leen los ficheros de dependencias del clon (sin `node_modules` ni enlaces que salgan de `CLONE_DIR`); nada se ejecuta. La lista está en `CLONE_DIR/.ominous/watch.json`, con permisos solo para tu usuario, y a OSV.dev solo van nombres y versiones de paquetes, igual que en el análisis. `OMINOUS_WATCH=0` la desactiva.

### Datos que se actualizan solos

Los avisos de las dependencias no caducan: se consultan en OSV.dev en cada análisis. Lo que sí envejece está en `data/`:

| Fichero | Qué es | Fuente |
|---|---|---|
| `data/kev.json` | CVE que se están explotando | catálogo KEV de CISA |
| `data/popular.json` | paquetes más descargados de npm y PyPI: objetivos de typosquatting y nombres legítimos que no se marcan | [npm-high-impact](https://github.com/wooorm/npm-high-impact) y [top-pypi-packages](https://github.com/hugovk/top-pypi-packages) |

Cada lunes, el workflow `update-data.yml` ejecuta `npm run update:data`, valida lo descargado, regenera `public/analyzer.js`, pasa lint y tests y, si algo ha cambiado, abre un PR para que lo revises. Nunca toca `main` directamente. Para que pueda abrir el PR, activa una vez *Settings > Actions > General > Allow GitHub Actions to create and approve pull requests*. En local: `npm run update:data`.

## Seguridad de la propia herramienta

- **Red:** por defecto solo escucha en `127.0.0.1` y rechaza cualquier `Host` que no sea de esta máquina (protección contra DNS rebinding) y cualquier POST con un `Origin` ajeno (CSRF). Las peticiones tienen que ser JSON y de 64 KB como mucho.
- **Exposición:** si se abre a otros nombres (`ALLOWED_HOSTS`/`ALLOW_ANY_HOST`) no arranca sin `OMINOUS_TOKEN`. El token se compara en tiempo constante y se guarda en una cookie `HttpOnly`, `SameSite=Strict` (y `Secure` detrás de HTTPS).
- **Disco:** los clones solo pueden ir dentro de `CLONE_DIR`, también si hay enlaces simbólicos por medio. Así se evita clonar en carpetas que se ejecutan solas, como `~/.vim/pack/*/start` o `~/.config/autostart`.
- **Abuso:** límite de análisis por IP, de análisis simultáneos y de tamaño del repo. Cada análisis corre en un hilo aparte con tiempo máximo, para que un fichero diseñado para bloquear analizadores (ReDoS) no deje colgada la app.
- **Navegador:** `Content-Security-Policy` estricta (el único script de la página se autoriza por su hash SHA-256, calculado al arrancar, y no se carga nada de terceros: las fuentes van en `public/fonts`), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy` y `Permissions-Policy`.
- **Procesos:** URLs validadas de forma estricta, git sin shell y endurecido, y errores internos que no exponen detalles.
- **Proyecto:** CI con CodeQL, autoescaneo, `npm audit`, Trivy sobre la imagen y Dependabot, usando solo acciones oficiales de GitHub fijadas por SHA (con la versión en un comentario; Dependabot las actualiza) y `persist-credentials: false` en cada checkout.

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
npm run build:web   # vuelve a generar public/analyzer.js tras cambiar lib/ o web/
```

Los tests generan sus repos trampa en una carpeta temporal en cada ejecución (`test/helpers/fixtures.js`). Así el repo no contiene ficheros que VS Code, pytest o Claude Code pudieran ejecutar al abrirlo.

`.github/workflows/ci.yml` corre en cada push y pull request:

| Job | Qué hace |
|---|---|
| `lint` | `npm run lint` |
| `bundle` | `public/analyzer.js` al día con `lib/` y `web/` |
| `test` | tests en Node 20, 22 y 24; en 22 con cobertura (resumen del job) y JUnit |
| `self-scan` | la herramienta se analiza a sí misma; en repos públicos los hallazgos salen en *Security > Code scanning* |
| `audit` | `npm audit` |
| `docker` | imagen con prueba de humo y escaneo Trivy; desde `main` y etiquetas se publica en `ghcr.io/alexdbdevops/ominous-security` |
| `package` | zip del código como artefacto |
| `pages` | versión web en GitHub Pages (solo en `main`) |
| `release` | release de GitHub al subir una etiqueta `vX.Y.Z` que coincida con `package.json` |

`codeql.yml` pasa CodeQL cada semana y en cada PR, `update-data.yml` refresca cada semana los [datos que envejecen](#datos-que-se-actualizan-solos) con un PR, y Dependabot vigila npm, las acciones y la imagen base.

Para publicar una versión, sube la versión en `package.json`, haz commit y ejecuta `git tag v1.0.1 && git push --tags`.

Al autoescanearse se excluyen `lib/rules.js`, `lib/decoder.js`, `lib/extra.js`, la página, `public/analyzer.js` (las mismas reglas empaquetadas) y este README: contienen las firmas que busca, igual que la base de firmas de un antivirus.

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
| Versión web: `Has llegado al límite de consultas a GitHub` | 60 consultas por hora por IP sin sesión. Espera a la hora indicada, pon un token en «Token de GitHub (opcional)» o usa el servidor local con `GITHUB_TOKEN` |
| Versión web: `No se pudo conectar con GitHub` dentro de claude.ai | El visor de artefactos puede bloquear conexiones externas. Abre la web publicada o el servidor local |
| `No se encuentra Claude Code` al conectar | Instálalo en el mismo equipo que la app (`npm install -g @anthropic-ai/claude-code`) o indica la ruta con `OMINOUS_CLAUDE_BIN`. Dentro de Docker no está disponible |
| `Claude Code está instalado pero sin sesión` | Ejecuta `claude` en una terminal e inicia sesión con tu cuenta Pro o Max |
| `la clave solo se puede escribir desde este mismo equipo o a través de HTTPS` | La app está expuesta sin HTTPS. Pon la clave en `ANTHROPIC_API_KEY` o publica la app detrás de un proxy con TLS |
| El puerto 8080 está ocupado | `OMINOUS_PORT=9090 scripts/local.sh` |
| CodeQL: `sin revisar: Python: … autobuild.sh` | Las versiones antiguas de CodeQL no funcionan con Python 3.13. Actualiza el *bundle* de CodeQL o pon antes en el `PATH` un `python3` 3.12 |
| CodeQL no aparece en la cobertura | No está en el `PATH` o el repo no tiene JavaScript/TypeScript, Python ni Ruby. Indica la ruta con `OMINOUS_CODEQL_BIN` |
| `Paquete publicado en npm: no se pudo comparar` | Sin conexión con el registro o el paquete pasa de 25 MB |
| La vigilancia dice `la carpeta ya no existe` | Has movido o borrado el clon. Pulsa **Dejar de vigilar** |

## Límites

Es análisis estático por patrones (y por recorridos de datos si tienes CodeQL): reduce mucho el riesgo, pero no es una garantía. Un atacante decidido puede esquivar reglas concretas o descargar el payload real en tiempo de ejecución desde un servidor (eso se marca, pero no se puede ver qué descargará). Analiza hasta 8000 ficheros de 1,5 MB como máximo. Los binarios de las releases y los ficheros de Git LFS no se descargan.

## Estructura

```
server.js            servidor HTTP, descarga, clonado, token y límites
bin/ominous-scan.js  escáner por línea de comandos (JSON, SARIF, Code Quality)
lib/analyzer.js      recorrido del repo, chequeos estructurales, veredicto, arreglos automáticos
lib/rules.js         reglas de vulnerabilidades y amenazas
lib/decoder.js       ingeniería inversa de payloads codificados o cifrados
lib/deps.js          dependencias (OSV.dev), typosquatting, CISA KEV y EPSS
lib/depsdev.js       dependencias indirectas de npm sin lockfile (deps.dev)
lib/beyond.js        paquete publicado en npm o PyPI y avisos del propio proyecto
lib/watch.js         vigilancia de los repos clonados
lib/extra.js         autoejecutables, agentes de IA, lockfiles, señuelos, ZIP, imágenes, homoglifos
lib/history.js       historial de git
lib/external.js      Gitleaks, Semgrep, Trivy y CodeQL si están instalados (opcional)
lib/summary.js       resumen del diff de los arreglos (Claude o local)
lib/ai.js            revisión con IA: selección de ficheros, prompt, esquema y validación
lib/connection.js    conexión con Claude: clave de la API o Claude Code con tu cuenta
lib/worker.js        hilo de análisis con tiempo máximo
lib/explain.js       fichas "¿Qué es esto?" de cada regla (CWE, por qué importa, qué comprobar)
lib/github.js        URL de GitHub, metadatos, renombrados, releases y Scorecard (servidor y web)
web/                 versión web: descarga desde GitHub (github.js), worker (entry.js) y shims de Node
public/index.html    interfaz (ediciones local, web y web-ai)
public/analyzer.js   analizador empaquetado para el navegador (generado, no editar)
public/fonts/        fuentes autoalojadas (OFL)
Dockerfile           imagen (usuario sin privilegios, tini, healthcheck)
compose.yaml         despliegue local endurecido; compose.lan.yaml lo abre a tu red con token
scripts/local.sh     construir y arrancar en local (local.ps1 en Windows)
scripts/build-site.js versión web para GitHub Pages (dist/ con la CSP en un meta)
scripts/build-web.js genera public/analyzer.js con esbuild
scripts/update-data.js refresca data/ (KEV y paquetes populares)
data/                datos que envejecen, actualizados cada semana por update-data.yml
lib/page.js          interfaz y CSP de cada edición
test/                tests con node --test
```

## Licencia

[MIT](LICENSE)
