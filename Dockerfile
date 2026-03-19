# Stage 1: Build
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config \
    libntl-dev libgmp-dev \
    libgrpc++-dev libprotobuf-dev protobuf-compiler-grpc \
    libssl-dev \
    libboost-system-dev libboost-thread-dev \
    libmpfr-dev \
    nasm \
    git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Build YYH26 upstream dependencies
RUN bash service/protocols/yyh26/vendor/setup.sh /usr/local

# Build the service with YYH26 support
RUN mkdir -p build && cd build \
    && cmake .. -DMPSI_BUILD_YYH26=ON -DYYH26_DEPS_PREFIX=/usr/local \
       -DMPSI_BUILD_TESTS=OFF \
    && make -j$(nproc)

# Stage 2: Runtime
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libntl44 libgmp10 \
    libgrpc++1.51 libprotobuf23 \
    libssl3 \
    libboost-system1.74.0 libboost-thread1.74.0 \
    openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /src/build/service/psi_party /app/psi_party
COPY --from=builder /src/build/service/psi_dealer /app/psi_dealer

# Copy any vendored shared libraries (e.g., libgazelle.so)
COPY --from=builder /usr/local/lib/libgazelle.so* /usr/local/lib/
RUN ldconfig

# Copy certificate generation script and entrypoint
COPY service/certs/gen_certs.sh /app/gen_certs.sh
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh /app/gen_certs.sh

# Add binaries to PATH
ENV PATH="/app:${PATH}"

ENTRYPOINT ["/app/docker-entrypoint.sh"]
