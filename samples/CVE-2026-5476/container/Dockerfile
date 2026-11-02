FROM fedora:41
RUN dnf install -y glibc.i686 libgcc.i686 python3 && dnf clean all

COPY container/leakd.py      /opt/cfs/leakd.py
COPY container/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 1234/udp 1235/udp 2234/udp 2235/udp 2223/tcp
ENTRYPOINT ["/entrypoint.sh"]
