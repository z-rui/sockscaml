FROM ocaml/opam:alpine-ocaml-5.4-flambda AS build

USER root
RUN apk add linux-headers gmp-dev gmp-static

USER opam
WORKDIR /home/opam/src

COPY --chown=opam:opam *.opam ./
RUN opam-2.5 install . --deps-only

COPY --chown=opam:opam . .
RUN echo '(lang dune 3.0)' > dune-workspace && \
    echo '(env (_ (flags (:standard -ccopt -s -ccopt -no-pie -ccopt -static))))' >> dune-workspace

RUN opam-2.5 exec -- dune build bin/server.exe --profile release

FROM alpine:latest
WORKDIR /app
COPY --from=build /home/opam/src/_build/default/bin/server.exe ./app

ENTRYPOINT ["./app"]
