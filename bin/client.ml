open Eio.Std

type config = {
  listen_addr : string;
  listen_port : int;
  dial_host : string;
  dial_service : string;
  identity_pub : string;
}

let load_config path =
  let open Otoml in
  try
    let t = Parser.from_file path in
    let remote_name = find t get_string [ "remote" ] in
    let r = find t get_value [ remote_name ] in
    Some
      {
        listen_addr =
          find_or ~default:"127.0.0.1" t get_string [ "listen_addr" ];
        listen_port = find t get_integer [ "listen_port" ];
        dial_host = find r get_string [ "addr" ];
        dial_service = find r (get_string ~strict:false) [ "port" ];
        identity_pub =
          find r (Fun.compose Base64.decode_exn get_string) [ "identity" ];
      }
  with Parse_error (loc, msg) ->
    (match loc with
    | Some (line, _) -> traceln "%s:%d: %s" path line msg
    | _ -> traceln "%s" msg);
    failwith "failed loading config file"

let handle_conn ~cfg net flow _addr ~signing_pubkey =
  Eio.Net.with_tcp_connect net ~host:cfg.dial_host ~service:cfg.dial_service
  @@ fun remote_flow ->
  let wrapped_remote = Sockscaml.Client.handshake remote_flow ~signing_pubkey in
  Fiber.first
    (fun () -> Eio.Flow.copy flow wrapped_remote)
    (fun () -> Eio.Flow.copy wrapped_remote flow)

let main ~net ~cfg =
  Switch.run ~name:"main" @@ fun sw ->
  let signing_pubkey =
    match Mirage_crypto_ec.Ed25519.pub_of_octets cfg.identity_pub with
    | Ok pub -> pub
    | Error e ->
        traceln "%a" Mirage_crypto_ec.pp_error e;
        failwith "cannot parse public key"
  in
  let stop_p, stop_r = Promise.create () in
  Sys.(set_signal sigint (Signal_handle (fun _ -> Promise.resolve stop_r ())));
  let sockaddr =
    `Tcp
      ( Ipaddr.(of_string_exn cfg.listen_addr |> to_octets)
        |> Eio.Net.Ipaddr.of_raw,
        cfg.listen_port )
  in
  traceln "Dial to %s:%s" cfg.dial_host cfg.dial_service;
  traceln "Listening on %a" Eio.Net.Sockaddr.pp sockaddr;
  Fiber.first (fun () -> Promise.await stop_p) @@ fun () ->
  let socket = Eio.Net.listen ~sw net sockaddr ~backlog:10 ~reuse_addr:true in
  Eio.Net.run_server socket
    (handle_conn ~cfg net ~signing_pubkey)
    ~on_error:(traceln "%a" Eio.Exn.pp)

let () =
  let cfg_path =
    match Sys.argv with [| _; path |] -> path | _ -> "config.ini"
  in
  match load_config cfg_path with
  | None -> failwith "cannot parse config file"
  | Some cfg ->
      Mirage_crypto_rng_unix.use_default ();
      Eio_main.run @@ fun env -> main ~net:(Eio.Stdenv.net env) ~cfg
