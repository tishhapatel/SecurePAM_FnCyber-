##############################################################################
# SecurePAM Browser Isolation Daemon — Dockerfile
# Member 11: Web Gateway & Browser Isolation
##############################################################################
#
# Provides isolated browser execution:
# - Chromium in headless / Xvfb virtual frame buffer
# - Isolated profile/user data dir per session
# - x11vnc / websockify for noVNC web streaming
# - Controlled HTTP management interface for backend
#
##############################################################################

FROM alpine:3.20

# Install Chromium, Xvfb, x11vnc, noVNC, websockify, and Python
RUN apk add --no-cache \
    chromium \
    xvfb \
    x11vnc \
    novnc \
    websockify \
    python3 \
    bash \
    procps \
    curl \
    ffmpeg \
    && rm -rf /var/cache/apk/*

WORKDIR /app

COPY server.py /app/server.py
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/server.py /app/entrypoint.sh

EXPOSE 6080

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python3", "/app/server.py"]
