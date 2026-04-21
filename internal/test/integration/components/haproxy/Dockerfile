FROM registry.access.redhat.com/ubi9/ubi-minimal:9.6@sha256:fe688da81a696387ca53a4c19231e99289591f990c904ef913c51b6e87d4e4df
RUN microdnf install -y haproxy && microdnf clean all
ENTRYPOINT ["haproxy"]
CMD ["-f", "/usr/local/etc/haproxy/haproxy.cfg"]
