(** Stripped-down version of SOCKS5 proxy implementation

    Caution: not RFC1928 compliant *)

val handle_client :
  _ Eio.Net.t -> _ Eio.Flow.two_way -> Eio.Net.Sockaddr.stream -> unit
(** [handle_client net flow addr] handles an incoming SOCKS5 connection
    represented by [flow] with peer addr [addr].

    This function may use [net] to resolve remote address and/or connect to the
    remote address as requested by the CONNECT command. *)
