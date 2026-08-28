FROM scratch
COPY --chmod=0555 open-card-static-server /open-card-static-server
COPY --chown=65532:65532 index.html /www/index.html
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/open-card-static-server","-root","/www","-listen",":8080"]
