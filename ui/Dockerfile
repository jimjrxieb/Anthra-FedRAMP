# DELIBERATELY INSECURE — runs as root, serves via nginx with no hardening
FROM node:20 AS build
WORKDIR /app
COPY package.json .
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
RUN rm -f /etc/nginx/conf.d/default.conf.bak
EXPOSE 8080

# Security: Run as non-root user (Hadolint DL3002, Checkov CKV_DOCKER_2)
RUN adduser --uid 10001 --disabled-password --no-create-home --shell /bin/false appuser
USER 10001
# Security: Health check for K8s liveness/readiness (Checkov CKV_DOCKER_3)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO /dev/null http://localhost:8080/ || exit 1

