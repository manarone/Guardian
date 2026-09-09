FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# Drop privileges: a compromise of the API process should not be root in the
# container. Done after the install so site-packages stay root-owned.
RUN useradd --create-home --uid 10001 guardian && chown -R guardian:guardian /app
USER guardian

EXPOSE 8000
CMD ["guardian"]
