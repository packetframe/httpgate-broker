FROM debian:bullseye
RUN apt update && apt install -y ca-certificates
COPY httpgate-broker /usr/bin/httpgate-broker
ENTRYPOINT ["/usr/bin/httpgate-broker"]
