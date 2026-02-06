# Build stage
FROM swift:5.9-jammy AS builder

WORKDIR /app

# Copy Package files first for dependency caching
COPY Package.swift Package.resolved ./

# Fetch dependencies
RUN swift package resolve

# Copy source code
COPY Sources/ Sources/
COPY Resources/ Resources/
COPY Public/ Public/
COPY Tests/ Tests/

# Build release binary
RUN swift build -c release --static-swift-stdlib

# Runtime stage
FROM ubuntu:jammy

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libcurl4 \
    libxml2 \
    ca-certificates \
    tzdata \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy built artifacts
COPY --from=builder /app/.build/release/App ./
COPY --from=builder /app/Resources/ ./Resources/
COPY --from=builder /app/Public/ ./Public/

# Create non-root user
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

# Environment
ENV ENVIRONMENT=production
ENV PORT=9873

EXPOSE 9873

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:9873/health || exit 1

ENTRYPOINT ["./App"]
CMD ["serve", "--env", "production", "--hostname", "0.0.0.0", "--port", "9873"]
