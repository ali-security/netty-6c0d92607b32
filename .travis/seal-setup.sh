# Sealed build environment setup, sourced by .travis.yml (before_install) and by
# .github/workflows/seal-build.yml. Do not use `set -e`: this file is sourced.
#
# 1. Zulu OpenJDK 7 ($SEAL_JDK): Netty 3.7.0.Final was released with JDK 1.7.0_25
#    and its enforcer rule requires Java >= 1.7. The current JDK's cacerts are
#    copied in so JDK 7 can reach Maven Central over TLS.
# 2. Maven $SEAL_MAVEN.
# 3. seal-java.security: the securechat example keystore used by the SSL echo
#    tests holds a 512-bit RSA certificate that 7u352's default
#    jdk.certpath/jdk.tls.disabledAlgorithms reject. Surefire runs with
#    forkMode=never, so the override passed through MAVEN_OPTS reaches the tests.
SEAL_JDK=${SEAL_JDK:-zulu7.56.0.11-ca-jdk7.0.352-linux_x64}
SEAL_MAVEN=${SEAL_MAVEN:-3.8.8}
SEAL_ROOT=$(pwd)
SEAL_CACERTS_SRC="${JAVA_HOME}/jre/lib/security/cacerts"
[ -f "$SEAL_CACERTS_SRC" ] || SEAL_CACERTS_SRC="${JAVA_HOME}/lib/security/cacerts"

curl -fsSL --retry 5 --retry-delay 10 -o /tmp/seal-jdk.tar.gz "https://cdn.azul.com/zulu/bin/${SEAL_JDK}.tar.gz" || return 1
mkdir -p /tmp/seal-jdk7 && tar -xzf /tmp/seal-jdk.tar.gz -C /tmp/seal-jdk7 --strip-components=1 || return 1
if [ -f "$SEAL_CACERTS_SRC" ]; then
  cp "$SEAL_CACERTS_SRC" /tmp/seal-jdk7/jre/lib/security/cacerts || return 1
fi
export JAVA_HOME=/tmp/seal-jdk7
export PATH="$JAVA_HOME/bin:$PATH"

curl -fsSL --retry 5 --retry-delay 10 -o /tmp/seal-maven.tar.gz \
  "https://archive.apache.org/dist/maven/maven-3/${SEAL_MAVEN}/binaries/apache-maven-${SEAL_MAVEN}-bin.tar.gz" || return 1
tar -xzf /tmp/seal-maven.tar.gz -C /tmp || return 1
export M2_HOME="/tmp/apache-maven-${SEAL_MAVEN}"
export PATH="$M2_HOME/bin:$PATH"
export MAVEN_OPTS="-Dhttps.protocols=TLSv1.2 -Djava.security.properties=${SEAL_ROOT}/.travis/seal-java.security"

java -version
mvn -version
