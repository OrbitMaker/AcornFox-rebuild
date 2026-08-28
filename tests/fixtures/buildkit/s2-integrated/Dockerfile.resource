FROM alpine:3.23.5

RUN dd if=/dev/zero of=/dev/shm/allocation bs=1M count=256
