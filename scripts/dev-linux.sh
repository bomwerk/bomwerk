#!/usr/bin/env bash
set -euo pipefail
docker build -f docker/dev.Dockerfile -t bomwerk-dev .
docker run --rm -it -v "$PWD":/src -w /src bomwerk-dev bash
