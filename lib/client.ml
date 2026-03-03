open Eio.Std
open Common

let handshake remote_flow ~signing_pubkey =
  let priv_key, pub_key = X25519.gen_key () in

  let client_hello = Cstruct.create sizeof_client_hello in
  set_client_hello_rnd (Mirage_crypto_rng.generate 8) 0 client_hello;
  set_client_hello_pub pub_key 0 client_hello;
  Eio.Flow.write remote_flow [ client_hello ];

  let server_hello = Cstruct.create sizeof_server_hello in
  Eio.Flow.read_exact remote_flow server_hello;

  let msg = sign_payload ~client_hello ~server_hello in
  let signature = copy_server_hello_sign server_hello in
  if not (Ed25519.verify ~key:signing_pubkey signature ~msg) then
    raise SignatureError;

  let server_pub_key = copy_server_hello_pub server_hello in
  let c_to_s, s_to_c =
    derive_cipher priv_key server_pub_key ~client_hello ~server_hello
  in
  Wrap.two_way ~read_processor:s_to_c ~write_processor:c_to_s remote_flow
