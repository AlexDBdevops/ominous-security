# Ominous Security en contenedor.
# En local, lo más sencillo es scripts/local.sh (usa compose.yaml). A mano:
#   docker build -t ominous-security .
#   docker run --rm -p 127.0.0.1:8080:8080 -v ominous-clones:/data --read-only --tmpfs /tmp \
#     --cap-drop ALL --security-opt no-new-privileges ominous-security
# También sirve como escáner en CI:
#   docker run --rm -v "$PWD:/src:ro" --entrypoint ominous-scan ghcr.io/alexdbdevops/ominous-security /src

FROM node:22-alpine
LABEL org.opencontainers.image.title="Ominous Security" \
      org.opencontainers.image.description="Analiza repositorios de GitHub antes de clonarlos" \
      org.opencontainers.image.source="https://github.com/AlexDBdevops/ominous-security" \
      org.opencontainers.image.licenses="MIT"
RUN apk add --no-cache git tini \
 && addgroup -S ominous && adduser -S -G ominous -h /home/ominous ominous \
 && mkdir -p /data && chown ominous:ominous /data

WORKDIR /app
COPY package.json package-lock.json ./
# npm, corepack y yarn solo hacen falta para instalar: fuera de la imagen final (el npm que trae
# la imagen base arrastra sus propias vulnerabilidades y la app no lo usa)
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force \
 && rm -rf /usr/local/lib/node_modules /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
      /usr/local/bin/yarn /usr/local/bin/yarnpkg /opt/yarn-* /tmp/* /root/.npm
COPY server.js ./
COPY lib ./lib
COPY data ./data
COPY bin ./bin
COPY public ./public
RUN ln -s /app/bin/ominous-scan.js /usr/local/bin/ominous-scan && chmod +x /app/bin/ominous-scan.js

# Dentro del contenedor escucha en todas las interfaces; publica el puerto
# solo en 127.0.0.1 del host (ver arriba). El servidor sigue rechazando
# cualquier Host que no sea localhost:8080.
ENV HOST=0.0.0.0 PORT=8080 CLONE_DIR=/data NODE_ENV=production HOME=/tmp
USER ominous
EXPOSE 8080
VOLUME ["/data"]
# Sin el proxy de salida (compose.yaml): la app se pregunta a sí misma, no a Internet.
HEALTHCHECK --interval=30s --timeout=3s CMD wget -Y off -qO- --header "Host: 127.0.0.1:8080" http://127.0.0.1:8080/api/health || exit 1
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "server.js"]
