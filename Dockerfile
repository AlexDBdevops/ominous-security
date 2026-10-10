# Ominous Security en contenedor.
#   docker run --rm -p 127.0.0.1:8080:8080 -v ominous-clones:/data registry.gitlab.com/<grupo>/ominous-security
# También sirve como escáner en CI:
#   docker run --rm -v "$PWD:/src:ro" --entrypoint ominous-scan registry.gitlab.com/<grupo>/ominous-security /src

FROM node:22-alpine
RUN apk add --no-cache git tini \
 && addgroup -S ominous && adduser -S -G ominous -h /home/ominous ominous \
 && mkdir -p /data && chown ominous:ominous /data

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY server.js ./
COPY lib ./lib
COPY bin ./bin
COPY public ./public
RUN ln -s /app/bin/ominous-scan.js /usr/local/bin/ominous-scan && chmod +x /app/bin/ominous-scan.js

# Dentro del contenedor escucha en todas las interfaces; publica el puerto
# solo en 127.0.0.1 del host (ver arriba). El servidor sigue rechazando
# cualquier Host que no sea localhost:8080.
ENV HOST=0.0.0.0 PORT=8080 CLONE_DIR=/data NODE_ENV=production
USER ominous
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- --header "Host: localhost:8080" http://127.0.0.1:8080/api/health || exit 1
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "server.js"]
