FROM alpine:3.23.5

ARG TASK_ID

RUN test ! -e /var/run/docker.sock && test ! -e /host
RUN awk 'BEGIN { value = "x"; for (i = 0; i < 22; i++) value = value value; print length(value) }' >/tmp/allocation-size

LABEL open-card.task=$TASK_ID

CMD ["sh", "-c", "cat /tmp/allocation-size"]
