external chacha20_init : Bigstringaf.t -> key:string -> nonce:string -> unit
  = "c_chacha20_init"
[@@noalloc]

external chacha20_block : Bigstringaf.t -> unit = "c_chacha20_block" [@@noalloc]

external chacha20_block_add : dst:Bigstringaf.t -> src:Bigstringaf.t -> unit
  = "c_chacha20_block_add"
[@@noalloc]

external chacha20_loopbody :
  out:Bigstringaf.t -> off:int -> dst:Bigstringaf.t -> src:Bigstringaf.t -> unit
  = "c_chacha20_loopbody"
[@@noalloc]

external xorblit : Bigstringaf.t -> int -> Bigstringaf.t -> int -> int -> unit
  = "c_chacha20_xorblit"
[@@noalloc]
