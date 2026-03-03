module X25519 = Mirage_crypto_ec.X25519
module Ed25519 = Mirage_crypto_ec.Ed25519

exception KeyExchangeError of Mirage_crypto_ec.error
exception SignatureError

[%%cstruct
type client_hello = { rnd : uint8_t; [@len 8] pub : uint8_t [@len 32] }
[@@little_endian]]

[%%cstruct
type server_hello = {
  rnd : uint8_t; [@len 32]
  pub : uint8_t; [@len 32]
  sign : uint8_t; [@len 64]
}
[@@little_endian]]

let stream_processor cipher buffer =
  let buf = Cstruct.to_bigarray buffer in
  Chacha20.crypt cipher buf

let sign_payload ~client_hello ~server_hello =
  let buf = Bytes.create 96 in
  Cstruct.blit_to_bytes server_hello 0 buf 0 64;
  Cstruct.blit_to_bytes client_hello 8 buf 64 32;
  Bytes.unsafe_to_string buf

let derive_cipher priv peer_pub ~client_hello ~server_hello =
  match X25519.key_exchange priv peer_pub with
  | Error e -> raise (KeyExchangeError e)
  | Ok shared_key ->
      let rnd = get_server_hello_rnd server_hello
      and rr = copy_client_hello_rnd client_hello in
      let nonce1 = Cstruct.to_string rnd ~off:0 ~len:12
      and nonce2 = Cstruct.to_string rnd ~off:12 ~len:12
      and salt = Cstruct.to_string rnd ~off:24 ~len:8 ^ rr in
      let key = Chacha20.hchacha20 ~key:shared_key ~nonce:salt in
      let c_to_s = Chacha20.create ~key ~nonce:nonce1 |> stream_processor
      and s_to_c = Chacha20.create ~key ~nonce:nonce2 |> stream_processor in
      (c_to_s, s_to_c)
