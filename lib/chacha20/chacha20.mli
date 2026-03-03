val key_size : int
val nonce_size : int
val block_size : int

type t
(** A stateful stream processor using the Chacha20 algorithm. *)

val create : key:string -> nonce:string -> t
(** [create ~key ~nonce] creates a new cipher using the given [key] and [nonce].
    The counter is initialized to zero.*)

val crypt : t -> Bigstringaf.t -> unit
(** [crypt t buf ~pos ~len] encrypts the content in-place of the [len] bytes in
    [buf] starting at [pos] with the current state of the cipher.

    The counter in the cipher is incremented every 64 bytes.

    If [buf] is not exactly a multiple of 64 bytes, partial key stream will be
    retained in the cipher and will be used for the next encryption. This means
    that calling [encrypt] multiple times has the same effect as calling it once
    with all the inputs concatenated.

    Decryption is the same as encryption.*)

val get_counter : t -> int32
(** [get_counter t] gets the current cipher counter. *)

val set_counter : t -> int32 -> unit
(** [set_counter t ctr] sets the current cipher counter to [ctr]. *)

val incr_counter : t -> unit
(** [incr_counter t] Increments the current cipher counter by one.

    @raise [CounterOverflow]
      when the counter is already the maximum possible value. *)

exception CounterOverflow

val hchacha20 : key:string -> nonce:string -> string
(** [hchacha20 key nonce] computes the hash of a 32-byte [key] with a 16-byte
    [nonce] using the HChacha20 algorithm. *)

val xorblit : Bigstringaf.t -> int -> Bigstringaf.t -> int -> int -> unit
(** [xorblit src src_pos dst dst_pos n] XORs each bit in [src] starting from
    [src_pos] (in bytes) into each bit in [dst] starting from [dst_size], with
    [n] bytes in total. *)
