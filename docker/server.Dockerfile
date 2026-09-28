# check=skip=InvalidDefaultArgInFrom
# SERVER_IMAGE has no default on purpose: the base must be the digest-pinned image
# for one specific major from docker/versions.json, and a default would silently
# build against the wrong server.
# The published server image: an official mysql image with component_gcm.so already in
# plugin_dir and an init script that installs it on first start.
#
# This is a *release* artifact. Tests deliberately do not use it — they docker cp the
# .so into an unmodified official image (stack-ci-docker rule), so nothing in CI
# depends on this file being correct in order to catch a component bug.
#
# Build args come from docker/versions.json through .github/workflows/release.yml:
#   SERVER_IMAGE  the digest-pinned official image for that major
#   SO_PATH       build context path of the component built for that same major
ARG SERVER_IMAGE
FROM ${SERVER_IMAGE}

ARG SO_PATH
ARG MYSQL_MAJOR
ARG GCM_VERSION

LABEL org.opencontainers.image.title="mysql-gcm server" \
      org.opencontainers.image.description="MySQL ${MYSQL_MAJOR} with the AES-256-GCM component preinstalled" \
      org.opencontainers.image.source="https://github.com/devgyurak/mysql-gcm" \
      org.opencontainers.image.version="${GCM_VERSION}" \
      org.opencontainers.image.licenses="GPL-2.0-only"

# plugin_dir differs between the official images, so it is resolved at build time from
# the server itself rather than hardcoded.
COPY ${SO_PATH} /tmp/component_gcm.so
RUN set -eux; \
    plugin_dir="$(mysqld --verbose --help 2>/dev/null | awk '$1 == "plugin-dir" { print $2; exit }')"; \
    test -n "${plugin_dir}"; \
    install -m 0644 /tmp/component_gcm.so "${plugin_dir}/component_gcm.so"; \
    rm -f /tmp/component_gcm.so; \
    echo "${plugin_dir}" > /etc/gcm-plugin-dir

# The official entrypoint runs everything in this directory on *first* start, i.e. when
# the data directory is empty. INSTALL COMPONENT writes to mysql.component in that data
# directory, so an image started against an existing volume will not be touched — see
# docs/ops-constraints.md item 14, which is the same reason every replica needs its own
# install.
COPY docker/install-component.sql /docker-entrypoint-initdb.d/00-gcm-install.sql
