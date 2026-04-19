FROM registry.access.redhat.com/ubi9/ubi-minimal:latest
RUN microdnf install -y haproxy && microdnf clean all
ENTRYPOINT ["haproxy"]
CMD ["-f", "/usr/local/etc/haproxy/haproxy.cfg"]
