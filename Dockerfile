FROM scratch
ADD build/simplomon simplomon

ADD certs.tar /

EXPOSE 8080

ENTRYPOINT ["/simplomon"]
