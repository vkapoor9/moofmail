# Moofmail phone access, for a Linux server or VPS that runs Docker.
#
# The image runs only the remote connector. cloudflared runs as a second
# container that shares this one's network (docker-compose.yml), so the server
# binds 127.0.0.1 and is still reached through the tunnel, with no port published.
FROM python:3.13-slim
COPY --from=ghcr.io/astral-sh/uv:0.12.22 /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY icloud_mcp ./icloud_mcp
RUN uv sync --frozen --no-dev && useradd --create-home --home-dir /srv/moofmail --uid 10001 moofmail
USER moofmail
ENV PATH="/app/.venv/bin:${PATH}"
CMD ["python", "-m", "icloud_mcp.transport"]
