val key_size : int
val nonce_size : int
val block_size : int

type t
(** A stateful stream processor using the Chacha20 algorithm. *)

exception CounterOverflow

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

    Decryption is the same as encryption.

    @raise CounterOverflow The 32-bit counter is exhausted. *)

val get_counter : t -> int32
(** [get_counter t] gets the current cipher counter. *)

val set_counter : t -> int32 -> unit
(** [set_counter t ctr] sets the current cipher counter to [ctr]. *)

val hchacha20 : key:string -> nonce:string -> string
(** [hchacha20 key nonce] computes the hash of a 32-byte [key] with a 16-byte
    [nonce] using the HChacha20 algorithm. *)
