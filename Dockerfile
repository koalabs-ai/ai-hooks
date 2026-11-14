# Tiny image for CI and for the MCP registry: only the static binary.
FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /ai-hooks ./cmd/ai-hooks

FROM scratch
LABEL io.modelcontextprotocol.server.name="io.github.koalabs-ai/ai-hooks"
LABEL org.opencontainers.image.source="https://github.com/koalabs-ai/ai-hooks"
LABEL org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /ai-hooks /ai-hooks
USER 65532:65532
ENTRYPOINT ["/ai-hooks"]
