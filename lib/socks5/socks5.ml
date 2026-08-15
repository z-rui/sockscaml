open Eio.Std
module Read = Eio.Buf_read
module Write = Eio.Buf_write
module Ipaddr = Eio.Net.Ipaddr

let socks_ver = '\x05'

let select_auth methods =
  (* Only NO AUTH is supported - not rfc1928 compliant *)
  if String.contains methods '\x00' then '\x00' else '\xff'

let ipaddr_to_raw addr = (addr : 'a Ipaddr.t :> string)

type error =
  | ServerFailure
  | Connection_not_allowed
  | Network_unreachable
  | Host_unreachable
  | Connection_refused
  | TTL_expired
  | Command_not_supported
  | Address_type_not_supported

exception E of error

let send_cmd_response sink ?(reply_field = '\x00') bind_addr bind_port =
  Write.with_flow sink @@ fun w ->
  Write.char w socks_ver;
  Write.char w reply_field;
  Write.char w '\x00';
  Write.char w
    (Ipaddr.fold ~v4:(fun _ -> '\x01') ~v6:(fun _ -> '\x04') bind_addr);
  Write.string w (ipaddr_to_raw bind_addr);
  Write.BE.uint16 w bind_port

let send_cmd_error sink err =
  let reply_field =
    match err with
    | ServerFailure -> '\x01'
    | Connection_not_allowed -> '\x02'
    | Network_unreachable -> '\x03'
    | Host_unreachable -> '\x04'
    | Connection_refused -> '\x05'
    | TTL_expired -> '\x06'
    | Command_not_supported -> '\x07'
    | Address_type_not_supported -> '\x08'
  in
  send_cmd_response sink ~reply_field Ipaddr.V4.any 0

let handle_connect_cmd net buf flow host service =
  Eio.Net.with_tcp_connect ~host ~service net @@ fun remote_socket ->
  (* FIXME: it is not possible to find BND.ADDR and BND.PORT from generic Eio interface *)
  let bind_addr = Ipaddr.V4.any in
  let bind_port = 0 in
  send_cmd_response flow bind_addr bind_port;
  Eio.Fiber.first
    (* client -> remote *)
    (fun () ->
      let leftover = Read.buffered_bytes buf in
      if leftover > 0 then
        Eio.Flow.copy_string (Read.take leftover buf) remote_socket;
      (* Now copy without the intermediate buffer *)
      Eio.Flow.copy flow remote_socket)
    (* remote -> client *)
    (fun () -> Eio.Flow.copy remote_socket flow)

let handle_socks5_cmd net buf flow =
  Read.char socks_ver buf;
  let cmd = Read.any_char buf in
  Read.char '\x00' buf;
  let atyp = Read.any_char buf in
  let dst_host =
    match atyp with
    | '\x03' (* domain name *) ->
        let len = Read.uint8 buf in
        Read.take len buf
    | _ ->
        let len =
          match atyp with
          | '\x01' (* IP V4 *) -> 4
          | '\x04' (* IP V6 *) -> 6
          | _ -> raise (E Address_type_not_supported)
        in
        Read.take len buf |> Ipaddr.of_raw |> Fmt.to_to_string Ipaddr.pp
  in
  let dst_service = Read.BE.uint16 buf |> Int.to_string in
  try
    match cmd with
    | '\x01' (* CONNECT *) ->
        handle_connect_cmd net buf flow dst_host dst_service
    (* BIND and UDP ASSOCIATE are not supported *)
    | _ -> raise (E Command_not_supported)
  with
  | Eio.Io (Eio.Net.E (Connection_failure (Refused _)), _) ->
      raise (E Connection_refused)
  | Eio.Io (Eio.Net.E (Connection_failure Timeout), _)
    ->
      raise (E Host_unreachable)
  | Eio.Io (Eio.Net.E (Address_lookup_failed _), _) ->
      raise (E Host_unreachable)
  | _ -> raise (E ServerFailure)

let handle_client net flow _addr =
  let buf = Read.of_flow flow ~initial_size:512 ~max_size:65536 in
  Read.char socks_ver buf;
  let nmethods = Read.uint8 buf in
  let methods = Read.take nmethods buf in
  let selected_method = select_auth methods in
  Write.with_flow flow (fun w ->
      Write.char w socks_ver;
      Write.char w selected_method);
  if selected_method <> '\xff' then
    try handle_socks5_cmd net buf flow with E e -> send_cmd_error flow e
