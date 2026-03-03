open Eio.Std

let listening_addr = ref Eio.Net.Ipaddr.V4.any
let listening_port = ref 1081
let identity_file = ref ".ss_identity"

let arg_spec =
  [
    ( "-i",
      Arg.Set_string identity_file,
      "identity file (private key in PEM format)" );
    ( "-l",
      Arg.String
        (fun s ->
          listening_addr :=
            Ipaddr.(of_string_exn s |> to_octets) |> Eio.Net.Ipaddr.of_raw),
      "listening address (default 0.0.0.0)" );
    ("-p", Arg.Set_int listening_port, "listening port (default 1081)");
  ]

let write_file path s =
  Out_channel.(
    with_open_gen [ Open_text; Open_wronly; Open_creat ] 0o600 path @@ fun f ->
    output_string f s)

let load_identity path =
  if path = "" then Mirage_crypto_ec.Ed25519.generate ()
  else if Sys.file_exists path then
    let pem = In_channel.(with_open_text path input_all) in
    match X509.Private_key.decode_pem pem with
    | Ok (`ED25519 priv) ->
        let pub = Mirage_crypto_ec.Ed25519.pub_of_priv priv in
        traceln "identity loaded from %s" path;
        (priv, pub)
    | Error (`Msg msg) -> failwith msg
    | _ -> failwith @@ "failed loading identity file at " ^ path
  else
    let priv, pub = Mirage_crypto_ec.Ed25519.generate () in
    X509.Private_key.encode_pem (`ED25519 priv) |> write_file path;
    (priv, pub)

let handle_conn ~signing_key net flow addr =
  let wrapped_flow = Sockscaml.Server.handshake flow ~signing_key in
  Socks5.handle_client net wrapped_flow addr

let main ~net =
  Switch.run ~name:"main" @@ fun sw ->
  let signing_key, signing_pub = load_identity !identity_file in
  traceln "My public key: %s"
    (Mirage_crypto_ec.Ed25519.pub_to_octets signing_pub |> Base64.encode_string);
  let sockaddr = `Tcp (!listening_addr, !listening_port) in
  traceln "listening on %a" Eio.Net.Sockaddr.pp sockaddr;
  let socket = Eio.Net.listen ~sw net sockaddr ~backlog:10 ~reuse_addr:true in
  Eio.Net.run_server socket
    (handle_conn net ~signing_key)
    ~on_error:(traceln "%a" Eio.Exn.pp)

let () =
  let usage = "ss-server [-l addr] [-p port]" in
  Arg.parse arg_spec ignore usage;
  Mirage_crypto_rng_unix.use_default ();
  Eio_main.run @@ fun env -> main ~net:(Eio.Stdenv.net env)
