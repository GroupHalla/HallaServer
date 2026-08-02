# Halla Server — build mínimo e enxuto
FROM debian:trixie-slim AS build
RUN apt-get update -qq && \
    apt-get install -y -qq cmake ninja-build g++ qt6-base-dev >/dev/null
WORKDIR /src
COPY . .
RUN cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build

FROM debian:trixie-slim
RUN apt-get update -qq && \
    apt-get install -y -qq libqt6core6t64 libqt6network6t64 >/dev/null && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /src/build/halla-server /usr/local/bin/halla-server
COPY halla-server.ini /etc/halla/halla-server.ini
VOLUME /data
WORKDIR /data
EXPOSE 9987/tcp 9987/udp
ENTRYPOINT ["halla-server", "--config", "/etc/halla/halla-server.ini"]
