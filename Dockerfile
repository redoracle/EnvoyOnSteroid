FROM ubuntu
MAINTAINER RedOracle

ARG BUILD_DATE
ARG VERSION
ARG VCS_URL
ARG VCS_REF

LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.vcs-url=$VCS_URL \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.version=$VERSION \
      org.label-schema.name='Envoy Container including ModSecurity v3 - WAF by Redoracle' \
      org.label-schema.description='UNOfficial Envoy Container including ModSecurity v3 - WAF docker image' \
      org.label-schema.usage='https://www.redoracle.com/docker/' \
      org.label-schema.url='https://www.redoracle.com/' \
      org.label-schema.vendor='RedOracle Security' \
      org.label-schema.schema-version='1.0' \
      org.label-schema.docker.cmd='docker run --rm redoracle/envoyonsteroid' \
      org.label-schema.docker.cmd.devel='docker run --rm -ti redoracle/envoyonsteroid' \
      org.label-schema.docker.debug='docker logs $CONTAINER' \
      io.github.offensive-security.docker.dockerfile="Dockerfile" \
      io.github.offensive-security.license="MIT" \
      MAINTAINER="RedOracle <info@redoracle.com>"

VOLUME /datak

RUN set -x \
    && apt-get update && apt-get -y upgrade  \
    && apt-get install -y build-essential software-properties-common bash gnupg openjdk-11-jdk pkg-config zip zlib1g-dev unzip python3 git htop vim wget tmux libtool cmake coreutils clang-format-5.0 automake g++ flex bison curl doxygen libyajl-dev libgeoip-dev libtool dh-autoreconf libcurl4-gnutls-dev libxml2 libpcre++-dev libxml2-dev \
    && rm -rf /var/lib/apt/lists/* && cd \
    && wget wget https://github.com/bazelbuild/bazel/releases/download/1.1.0/bazel-1.1.0-linux-x86_64 \
    && chmod +x bazel-1.1.0-linux-x86_64 \
    && mv bazel-1.1.0-linux-x86_64 /bin/bazel \
    && cd \
    && git clone https://github.com/octarinesec/ModSecurity-envoy.git \
    && git clone https://github.com/SpiderLabs/ModSecurity.git \
    && cd ModSecurity && git submodule update --init && ./build.sh \
    && ./configure && make && cd \
    && cd ModSecurity-envoy && git submodule update --init \
    && bazel build //:envoy \
    && mkdir ../conf && cd ../conf \
    && wget https://github.com/SpiderLabs/owasp-modsecurity-crs/releases/latest \
    && DFILE=$(cat latest | grep tar.gz | grep href | cut -d "\"" -f 2) \
    && wget https://github.com$DFILE \
    && rm latest && tar xzvf *.tar.gz && rm *.tar.gz \
    && cd
     
# Set environment variables.
ENV \
HOME /root \

# Define working directory.
WORKDIR /root

# Add files.
ADD root/.bashrc /root/.bashrc

# Define default command.
CMD ["bash"]

EXPOSE 9001 3100 3000 3101
