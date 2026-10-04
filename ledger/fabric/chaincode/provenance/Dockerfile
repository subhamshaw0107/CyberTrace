# Builds offline from the vendored module tree (run `go mod vendor` once while online).
FROM golang:alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -mod=vendor -o /provenance .

FROM alpine
COPY --from=build /provenance /provenance
EXPOSE 9999
CMD ["/provenance"]
