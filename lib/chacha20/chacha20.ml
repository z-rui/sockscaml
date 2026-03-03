let key_size = 32
let nonce_size = 12
let nonce_size_h = 16
let block_size = 64

let hchacha20 ~key ~nonce =
  if String.length key <> key_size then invalid_arg "bad key length";
  if String.length nonce <> nonce_size_h then invalid_arg "bad nounce length";
  let buf = Bigstringaf.create block_size in
  Unsafe.chacha20_init buf ~key ~nonce;
  Unsafe.chacha20_block buf;
  Bigstringaf.blit buf ~src_off:48 buf ~dst_off:16 ~len:16;
  Bigstringaf.substring buf ~off:0 ~len:32

let check_bounds size pos len =
  if pos < 0 || pos > size then invalid_arg "bad pos";
  if len < 0 || len > size - pos then invalid_arg "bad len"

let xorblit src src_pos dst dst_pos n =
  check_bounds (Bigstringaf.length src) src_pos n;
  check_bounds (Bigstringaf.length dst) dst_pos n;
  Unsafe.xorblit src src_pos dst dst_pos n

type t = {
  buf : Bigstringaf.t;  (** current block of key stream *)
  init : Bigstringaf.t;  (** init state = (c, key, ctr, nonce) *)
  mutable pos : int;  (** consumed bytes in buf *)
}

let[@inline] get_counter t = Bigstringaf.unsafe_get_int32_le t.init 48
let[@inline] set_counter t ctr = Bigstringaf.unsafe_set_int32_le t.init 48 ctr

let create ~key ~nonce =
  if String.length key <> key_size then invalid_arg "bad key length";
  if String.length nonce <> nonce_size then invalid_arg "bad nonce length";
  let state =
    {
      buf = Bigstringaf.create block_size;
      init = Bigstringaf.create block_size;
      pos = 0;
    }
  in
  Unsafe.chacha20_init state.init ~key ~nonce;
  state

exception CounterOverflow

let incr_counter t =
  let ctr = get_counter t in
  if ctr = Int32.max_int then raise CounterOverflow;
  set_counter t (Int32.add ctr 1l)

let crypt_core t buf ~off ~len =
  assert (t.pos = 0);
  assert (len > 0);
  let rec loop off len =
    Unsafe.chacha20_block_add ~dst:t.buf ~src:t.init;
    if len > block_size then begin
      Unsafe.xorblit t.buf 0 buf off block_size;
      incr_counter t;
      loop (off + block_size) (len - block_size)
    end
    else if len > 0 then begin
      Unsafe.xorblit t.buf 0 buf off len;
      t.pos <- len
    end
  in
  loop off len

let crypt t buf =
  let len = Bigstringaf.length buf in
  if len > 0 then
    if t.pos = 0 then crypt_core t buf ~off:0 ~len
    else
      let n = block_size - t.pos in
      if len < n then begin
        Unsafe.xorblit t.buf t.pos buf 0 len;
        t.pos <- t.pos + len
      end
      else begin
        assert (n >= 0);
        if n > 0 then Unsafe.xorblit t.buf t.pos buf 0 n;
        t.pos <- 0;
        incr_counter t;
        if len > n then crypt_core t buf ~off:n ~len:(len - n)
      end
