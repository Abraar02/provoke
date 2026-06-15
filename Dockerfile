# Multi-stage build: build a wheel, then install it into a slim runtime image.
FROM python:3.13-slim AS build
WORKDIR /src
RUN pip install --no-cache-dir build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m build --wheel

FROM python:3.13-slim
# Run as a non-root user.
RUN useradd --create-home --uid 10001 provoke
COPY --from=build /src/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl
USER provoke
WORKDIR /work
ENTRYPOINT ["provoke"]
CMD ["--help"]
