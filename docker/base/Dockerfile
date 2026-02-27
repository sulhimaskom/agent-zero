# Use Debian 13 slim
FROM debian:13-slim

# Build arguments for locale and timezone (configurable at build time)
ARG LOCALE=en_US.UTF-8
ARG TZ=UTC

# Set locale and timezone
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y locales tzdata
RUN sed -i -e "s/# \(${LOCALE} .*\)/\1/" /etc/locale.gen && \
    dpkg-reconfigure --frontend=noninteractive locales && \
    update-locale LANG=${LOCALE} LANGUAGE=en_US:en LC_ALL=${LOCALE}
RUN ln -sf /usr/share/zoneinfo/${TZ} /etc/localtime
RUN echo "${TZ}" > /etc/timezone
RUN dpkg-reconfigure -f noninteractive tzdata
ENV LANG=${LOCALE}
ENV LANGUAGE=en_US:en
ENV LC_ALL=${LOCALE}
ENV TZ=${TZ}

# Copy contents of the project to /
COPY ./fs/ /

# install packages software (split for better cache management)
RUN bash /ins/install_base_packages1.sh
RUN bash /ins/install_base_packages2.sh
RUN bash /ins/install_base_packages3.sh
RUN bash /ins/install_base_packages4.sh

# install python after packages to ensure version overriding
RUN bash /ins/install_python.sh

# install searxng
RUN bash /ins/install_searxng.sh

# configure ssh
RUN bash /ins/configure_ssh.sh

# after install
RUN bash /ins/after_install.sh

# Create non-root user for security (principle of least privilege)
RUN groupadd -g 1000 agentzero && \
    useradd -r -u 1000 -g agentzero -d /home/agentzero -s /bin/bash agentzero && \
    mkdir -p /home/agentzero && \
    chown -R agentzero:agentzero /home/agentzero

# Set ownership for runtime directories
RUN mkdir -p /var/run /tmp /var/log && \
    chown -R agentzero:agentzero /var/run /tmp /var/log

# Switch to non-root user
USER agentzero

# Keep container running infinitely
CMD ["tail", "-f", "/dev/null"]
