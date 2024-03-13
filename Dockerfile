FROM scratch
ADD build/simplomon simplomon

ADD certs.tar /
ENTRYPOINT ["/simplomon"]
