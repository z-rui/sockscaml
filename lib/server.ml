open Eio.Std
open Common

let handshake remote_flow ~signing_key =
  let priv_key, pub_key = X25519.gen_key () in

  let client_hello = Cstruct.create sizeof_client_hello in
  Eio.Flow.read_exact remote_flow client_hello;

  let server_hello = Cstruct.create sizeof_server_hello in
  set_server_hello_rnd (Mirage_crypto_rng.generate 32) 0 server_hello;
  set_server_hello_pub pub_key 0 server_hello;
  set_server_hello_sign
    (Ed25519.sign ~key:signing_key (sign_payload ~client_hello ~server_hello))
    0 server_hello;
  Eio.Flow.write remote_flow [ server_hello ];

  let client_pub_key = copy_client_hello_pub client_hello in
  let c_to_s, s_to_c =
    derive_cipher priv_key client_pub_key ~client_hello ~server_hello
  in
  Wrap.two_way ~read_processor:c_to_s ~write_processor:s_to_c remote_flow
