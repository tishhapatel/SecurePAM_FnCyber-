##############################################################################
# SecurePAM NGINX Gateway — Dockerfile
# Member 11: Web Gateway & Browser Isolation
##############################################################################
#
# Uses the official NGINX unprivileged image.
# Environment variables are substituted at container startup via envsubst
# so that no secrets land in the image layer.
#
# Build context: gateway/nginx/
# Usage: docker compose --profile gateway up --build
##############################################################################

FROM nginx:1.27-alpine

# Remove the default NGINX configuration
RUN rm -rf /etc/nginx/conf.d/default.conf /etc/nginx/nginx.conf

# Copy our configuration template
COPY nginx.conf /etc/nginx/nginx.conf.template

# Copy entrypoint that runs envsubst before starting NGINX
COPY docker-entrypoint.sh /docker-entrypoint-gateway.sh
COPY nginx-reload-watcher.sh /nginx-reload-watcher.sh
RUN chmod +x /docker-entrypoint-gateway.sh /nginx-reload-watcher.sh

# Ensure NGINX can write its PID to /tmp (avoids permission issues)
RUN touch /tmp/nginx.pid && chown nginx:nginx /tmp/nginx.pid

EXPOSE 7000

ENTRYPOINT ["/docker-entrypoint-gateway.sh"]
CMD ["nginx", "-g", "daemon off;"]
