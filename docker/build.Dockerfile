# A *configured* MySQL source tree. Only cmake's configure step runs here, so the
# expensive part lands in a cached image layer (ci-release skill, cache key =
# this file + versions.json[ver]) while component sources stay outside the image:
# build-component.sh compiles them from a bind mount, so editing src/ never
# invalidates this image.
#
# Base image is digest-pinned (stack-ci-docker rule). Oracle Linux 9 is the same
# family as the official mysql images, so the component links the same OpenSSL
# generation the server loads (crypto-safety: never bundle a second libcrypto).
FROM oraclelinux:9@sha256:b14adaf5e90e551efe477483f8766d662057f4b3e8c12283f25375641223ed53

# All three come from docker/versions.json, which is the single source of truth
# (stack-ci-docker rule); scripts/build-in-docker.sh passes them.
ARG MYSQL_VERSION
ARG MYSQL_SOURCE_SHA256
ARG RHEL9_TOOLSET
RUN test -n "${MYSQL_VERSION}" && test -n "${MYSQL_SOURCE_SHA256}" && test -n "${RHEL9_TOOLSET}" \
    || { echo "MYSQL_VERSION, MYSQL_SOURCE_SHA256 and RHEL9_TOOLSET build-args are required" >&2; \
         exit 1; }

ENV MYSQL_SRC=/mysql-src
ENV MYSQL_BUILD=/mysql-build

# The source download comes before the toolchain so that changing packages below
# does not re-download several hundred MB.
#
# 8.0 still wants an external boost (cmake/boost.cmake looks for boost_1_77_0), so
# it uses the mysql-boost source bundle. 8.4 and 9.x vendor boost in extra/boost
# and accept no boost flag at all.
RUN set -eux; \
    major="$(echo "${MYSQL_VERSION}" | cut -d. -f1,2)"; \
    case "${major}" in \
      8.0) tarball="mysql-boost-${MYSQL_VERSION}.tar.gz" ;; \
      *)   tarball="mysql-${MYSQL_VERSION}.tar.gz" ;; \
    esac; \
    curl -fsSL -o /tmp/src.tar.gz \
      "https://dev.mysql.com/get/Downloads/MySQL-${major}/${tarball}"; \
    echo "${MYSQL_SOURCE_SHA256}  /tmp/src.tar.gz" | sha256sum -c -; \
    mkdir -p "${MYSQL_SRC}"; \
    tar -xzf /tmp/src.tar.gz --strip-components=1 -C "${MYSQL_SRC}"; \
    rm -f /tmp/src.tar.gz

# The annobin packages belong to the toolset, not to the base gcc: the distribution's
# hardening specs (-specs=.../redhat-annobin-cc1, pulled in with redhat-rpm-config)
# load plugin/annobin.so, and without the toolset's copy every compile dies with
# "inaccessible plugin file plugin/annobin.so". MySQL's own cmake message lists them.
#
# Each server version pins the compiler it expects on RHEL9 in its own
# CMakeLists.txt (ALTERNATIVE_PATHS under LINUX_RHEL9); versions.json records which,
# so the fact lives in one place. Installing the wrong one fails configure with
# "Could not find devtoolset compiler/linker". MySQL's cmake picks the toolset up
# from /opt/rh itself, so nothing needs to `scl enable` it.
# CodeReady Builder carries ninja-build, libtirpc-devel and rpcgen on OL9.
RUN set -eux; \
    toolset="${RHEL9_TOOLSET}"; \
    dnf -y install dnf-plugins-core; \
    dnf config-manager --set-enabled ol9_codeready_builder; \
    dnf -y install \
      "${toolset}-gcc" "${toolset}-gcc-c++" "${toolset}-binutils" \
      "${toolset}-annobin-annocheck" "${toolset}-annobin-plugin-gcc" \
      cmake ninja-build make patch tar gzip bzip2 findutils \
      openssl-devel ncurses-devel libtirpc-devel rpcgen bison zlib-devel \
      binutils elfutils libaio-devel pkgconf-pkg-config \
      perl perl-Data-Dumper perl-Getopt-Long perl-Time-HiRes perl-JSON-PP \
      perl-Digest-MD5 perl-Socket; \
    dnf clean all

# WITH_SSL=system: use the distribution libcrypto, never a bundled copy.
# WITH_UNIT_TESTS=OFF: the server's own gtest suite is not what we build here.
# perl is installed above on purpose: cmake bakes PERL_EXECUTABLE into
# mysql-test/mysql-test-run.pl at configure time, and without it MTR fails with
# "PERL_EXECUTABLE-NOTFOUND: bad interpreter".
RUN set -eux; \
    major="$(echo "${MYSQL_VERSION}" | cut -d. -f1,2)"; \
    boost_arg=""; \
    if [ "${major}" = "8.0" ]; then boost_arg="-DWITH_BOOST=${MYSQL_SRC}/boost"; fi; \
    cmake -S "${MYSQL_SRC}" -B "${MYSQL_BUILD}" -G Ninja \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DWITH_SSL=system \
      -DWITH_UNIT_TESTS=OFF \
      ${boost_arg}

COPY build-component.sh /usr/local/bin/build-component.sh
RUN chmod +x /usr/local/bin/build-component.sh

CMD ["/usr/local/bin/build-component.sh"]
