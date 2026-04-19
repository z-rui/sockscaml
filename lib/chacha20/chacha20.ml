let key_size = 32
let nonce_size = 12
let nonce_size_h = 16
let block_size = 64

type t

exception CounterOverflow

module Unsafe = struct
  external create : key:string -> nonce:string -> t = "c_chacha20_create"

  external crypt : t -> buf:Bigstringaf.t -> off:int -> len:int -> int
    = "c_chacha20_crypt"
  [@@noalloc]

  external hchacha20 : key:string -> nonce:string -> string = "c_hchacha20"
end

let hchacha20 ~key ~nonce =
  if String.length key <> key_size then invalid_arg "bad key length";
  if String.length nonce <> nonce_size_h then invalid_arg "bad nounce length";
  Unsafe.hchacha20 ~key ~nonce

let create ~key ~nonce =
  if String.length key <> key_size then invalid_arg "bad key length";
  if String.length nonce <> nonce_size then invalid_arg "bad nonce length";
  Unsafe.create ~key ~nonce

external get_counter : t -> int32 = "c_chacha20_get_counter"
external set_counter : t -> int32 -> unit = "c_chacha20_set_counter" [@@noalloc]

let crypt t buf =
  let len = Bigstringaf.length buf in
  if Unsafe.crypt t ~buf ~off:0 ~len = 1 then raise CounterOverflow
