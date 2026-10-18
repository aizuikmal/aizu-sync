# obsyncd: static binary (pure-Go SQLite, no cgo) on distroless, running as non-root.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/obsyncd . && mkdir /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/obsyncd /usr/local/bin/obsyncd
COPY --from=build --chown=65532:65532 /out/data /data
ENV OBSYNC_DATA=/data
VOLUME /data
EXPOSE 8787
ENTRYPOINT ["obsyncd"]
CMD ["serve", "-listen", ":8787"]
