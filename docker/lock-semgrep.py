# Genera docker/semgrep-requirements.txt con versiones y hashes fijados.
# Se ejecuta en la misma plataforma que la imagen (Debian 13, Python 3.13, x86_64):
#   docker run --rm -v "$PWD/docker:/out" python:3.13-slim-trixie python /out/lock-semgrep.py 1.178.0
import json, subprocess, sys

version = sys.argv[1]
subprocess.run([sys.executable, '-m', 'pip', 'install', '-q', '--root-user-action=ignore', '--dry-run', '--ignore-installed',
                '--only-binary', ':all:', '--report', '/tmp/report.json', f'semgrep=={version}'], check=True)
items = json.load(open('/tmp/report.json'))['install']
lines = [f'# semgrep {version} y sus dependencias, solo ruedas (sin ejecutar setup.py), con hashes.',
         '# Regenerar con docker/lock-semgrep.py (ver la cabecera del script).']
for it in sorted(items, key=lambda x: x['metadata']['name'].lower()):
    sha = it['download_info']['archive_info']['hashes']['sha256']
    lines.append(f"{it['metadata']['name']}=={it['metadata']['version']} --hash=sha256:{sha}")
open('/out/semgrep-requirements.txt', 'w').write('\n'.join(lines) + '\n')
print(len(items), 'paquetes')
