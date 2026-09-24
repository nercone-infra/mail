FROM debian:trixie-slim AS openssl-builder

ARG TRIXIE_PACKAGES_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY <<'EOF' /usr/local/bin/openssl-install
#!/bin/sh
set -eu

VERSION="$1"
TARGET="$2"

case "${TARGETARCH}" in
    amd64) ARCH=x86_64 ;;
    arm64) ARCH=aarch64 ;;
    *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;;
esac

NAME="openssl-${VERSION}-linux-${ARCH}"
URL="https://github.com/nercone-infra/openssl/releases/download/openssl-${VERSION}"
SOURCE=$(mktemp -d)

echo "Installing OpenSSL ${VERSION} (${NAME})"

curl -fsSL -o "${SOURCE}/${NAME}.tar.gz" "${URL}/${NAME}.tar.gz"
curl -fsSL "${URL}/SHA256SUMS" | grep "  ${NAME}.tar.gz\$" | (cd "${SOURCE}" && sha256sum -c -)
mkdir -p "${SOURCE}/openssl"
tar xzf "${SOURCE}/${NAME}.tar.gz" -C "${SOURCE}/openssl" --strip-components=1

if [ -d "${SOURCE}/openssl/lib64" ]; then
    LIBRARY="${SOURCE}/openssl/lib64"
else
    LIBRARY="${SOURCE}/openssl/lib"
fi

DIRECTORY=$(LD_LIBRARY_PATH="${LIBRARY}" "${SOURCE}/openssl/bin/openssl" version -d | sed -n 's/^OPENSSLDIR: "\(.*\)"$/\1/p')

mkdir -p "${TARGET}/bin" "${TARGET}/lib" "${TARGET}/ssl" "${TARGET}/include" "${TARGET}/root${DIRECTORY%/*}"
cp -a "${SOURCE}/openssl/bin/openssl" "${TARGET}/bin/"
cp -a "${LIBRARY}"/libssl.so* "${LIBRARY}"/libcrypto.so* "${TARGET}/lib/"
cp -a "${SOURCE}/openssl/ssl/openssl.cnf" "${TARGET}/ssl/"
cp -a "${SOURCE}/openssl/include/openssl" "${TARGET}/include/"
ln -s /etc/ssl/certs "${TARGET}/ssl/certs"
ln -s /etc/ssl/certs/ca-certificates.crt "${TARGET}/ssl/cert.pem"
ln -s /usr/local/ssl "${TARGET}/root${DIRECTORY}"
chown -hR root:root "${TARGET}"
rm -rf "${SOURCE}"
EOF

RUN chmod +x /usr/local/bin/openssl-install

FROM openssl-builder AS openssl3

ARG TARGETARCH
ARG OPENSSL3_VERSION

RUN openssl-install "${OPENSSL3_VERSION}" /opt/openssl

FROM debian:trixie-slim AS postfix

ARG TRIXIE_PACKAGES_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends postfix postfix-pgsql postfix-pcre gettext-base ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=openssl3 /opt/openssl/bin/ /usr/local/bin/
COPY --from=openssl3 /opt/openssl/lib/ /usr/local/lib/
COPY --from=openssl3 /opt/openssl/ssl/ /usr/local/ssl/
COPY --from=openssl3 /opt/openssl/root/ /

RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/00-openssl.conf && ldconfig

COPY postfix/entrypoint.sh /usr/local/bin/entrypoint.sh

EXPOSE 25 587 10025

STOPSIGNAL SIGTERM

CMD ["/usr/local/bin/entrypoint.sh"]

FROM debian:trixie-slim AS dovecot

ARG TRIXIE_PACKAGES_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends \
        dovecot-core dovecot-imapd dovecot-lmtpd dovecot-sieve dovecot-managesieved dovecot-pgsql \
        gettext-base curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=openssl3 /opt/openssl/bin/ /usr/local/bin/
COPY --from=openssl3 /opt/openssl/lib/ /usr/local/lib/
COPY --from=openssl3 /opt/openssl/ssl/ /usr/local/ssl/
COPY --from=openssl3 /opt/openssl/root/ /

RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/00-openssl.conf && ldconfig

RUN groupadd -g 5000 vmail && useradd -u 5000 -g vmail -s /usr/sbin/nologin -d /srv/vmail vmail \
    && mkdir -p /srv/vmail && chown vmail:vmail /srv/vmail

COPY dovecot/entrypoint.sh /usr/local/bin/entrypoint.sh

EXPOSE 24 143 4190 12345

STOPSIGNAL SIGTERM

CMD ["/usr/local/bin/entrypoint.sh"]

FROM python:3-slim-trixie AS auth

COPY --from=openssl3 /opt/openssl/bin/ /usr/local/bin/
COPY --from=openssl3 /opt/openssl/lib/ /usr/local/lib/
COPY --from=openssl3 /opt/openssl/ssl/ /usr/local/ssl/
COPY --from=openssl3 /opt/openssl/root/ /

RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/00-openssl.conf && ldconfig

WORKDIR /srv

COPY auth/auth.py /srv/auth.py

USER nobody

EXPOSE 10080

STOPSIGNAL SIGTERM

CMD ["python3", "-u", "/srv/auth.py"]

FROM debian:trixie-slim AS roundcube

ARG TRIXIE_PACKAGES_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends \
        php8.4-fpm php8.4-pgsql php8.4-intl php8.4-mbstring php8.4-gd php8.4-zip \
        php8.4-xml php8.4-curl php8.4-ldap php8.4-bcmath \
        gnupg curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=openssl3 /opt/openssl/bin/ /usr/local/bin/
COPY --from=openssl3 /opt/openssl/lib/ /usr/local/lib/
COPY --from=openssl3 /opt/openssl/ssl/ /usr/local/ssl/
COPY --from=openssl3 /opt/openssl/root/ /

RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/00-openssl.conf && ldconfig

ARG ROUNDCUBE_VERSION

RUN echo "Installing Roundcube ${ROUNDCUBE_VERSION}" \
    && curl -fsSL "https://github.com/roundcube/roundcubemail/releases/download/${ROUNDCUBE_VERSION}/roundcubemail-${ROUNDCUBE_VERSION}-complete.tar.gz" \
        | tar xz -C /tmp \
    && mv "/tmp/roundcubemail-${ROUNDCUBE_VERSION}" /opt/roundcube \
    && rm -rf /opt/roundcube/installer /tmp/roundcubemail-*

RUN rm -f /etc/php/8.4/fpm/pool.d/www.conf \
    && sed -i 's#^error_log = .*#error_log = /proc/self/fd/2#' /etc/php/8.4/fpm/php-fpm.conf

COPY roundcube/etc/php-fpm.conf /etc/php/8.4/fpm/pool.d/roundcube.conf

COPY roundcube/entrypoint.sh /usr/local/bin/entrypoint.sh

EXPOSE 9000

STOPSIGNAL SIGQUIT

CMD ["/usr/local/bin/entrypoint.sh"]

FROM debian:trixie-slim AS rspamd

ARG TRIXIE_PACKAGES_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends rspamd gettext-base ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=openssl3 /opt/openssl/bin/ /usr/local/bin/
COPY --from=openssl3 /opt/openssl/lib/ /usr/local/lib/
COPY --from=openssl3 /opt/openssl/ssl/ /usr/local/ssl/
COPY --from=openssl3 /opt/openssl/root/ /

RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/00-openssl.conf && ldconfig

COPY rspamd/entrypoint.sh /usr/local/bin/entrypoint.sh

EXPOSE 11332 11333 11334

STOPSIGNAL SIGTERM

CMD ["/usr/local/bin/entrypoint.sh"]
