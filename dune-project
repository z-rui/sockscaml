(lang dune 3.21)

(name sockscaml)

(generate_opam_files true)

(authors "张睿 <zrui16@hotmail.com>")

(maintainers "张睿 <zrui16@hotmail.com>")

(license MIT)

(package
 (name sockscaml)
 (synopsis "SOCKS in OCaml")
 (description "An encrypted Socks5 protocol written in OCaml")
 (depends
  ocaml
  base64
  bigstringaf
  cstruct
  ppx_cstruct
  ISO8601
  eio
  eio_main
  ipaddr
  mirage-crypto-ec
  mirage-crypto-rng
  sexplib
  ppx_sexp_conv
  x509))

; See the complete stanza docs at https://dune.readthedocs.io/en/stable/reference/dune-project/index.html
