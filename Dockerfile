FROM ocaml/opam:alpine-ocaml-5.4-flambda AS build

USER root
RUN apk add linux-headers gmp-dev

USER opam
WORKDIR /home/opam/src

COPY --chown=opam:opam *.opam ./
RUN opam install . --deps-only --with-test

COPY --chown=opam:opam . .
RUN opam exec -- dune build @install --profile release

FROM alpine:latest
RUN apk add gmp
WORKDIR /app
COPY --from=build /home/opam/src/_build/install/default/bin/ss-server ./app

ENTRYPOINT ["./app"]
