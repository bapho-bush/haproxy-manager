ARG BASE=ubuntu:24.04
FROM ${BASE}
RUN if command -v apt-get >/dev/null; then \
      apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3 python3-flask python3-requests python3-waitress python3-pampy \
        libpam-modules libpam-runtime passwd ca-certificates; \
    else \
      if grep -q 'ID="rocky"' /etc/os-release; then dnf -y install epel-release; fi; \
      dnf -y install python3 python3-flask python3-requests python3-waitress python3-pam \
        pam shadow-utils authselect ca-certificates; \
    fi
RUN if [ -f /etc/pam.d/common-auth ]; then \
      printf 'auth include common-auth\naccount include common-account\n' > /etc/pam.d/haproxy-manager; \
    else \
      if [ ! -f /etc/pam.d/system-auth ]; then authselect select minimal --force; fi; \
      printf 'auth include system-auth\naccount include system-auth\n' > /etc/pam.d/haproxy-manager; \
    fi
WORKDIR /app
CMD ["python3", "tools/test-pam.py"]
