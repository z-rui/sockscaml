open Eio.Std

let listening_addr = ref Eio.Net.Ipaddr.V4.loopback
let listening_port = ref 1080
let dial_addr = ref ""
let dial_port = ref ""
let identity_pub = ref "identity.pub"

let arg_spec =
  [
    ( "-l",
      Arg.String
        (fun s ->
          listening_addr :=
            Ipaddr.(of_string_exn s |> to_octets) |> Eio.Net.Ipaddr.of_raw),
      "listening address (default 127.0.0.1)" );
    ("-p", Arg.Set_int listening_port, "listening port (default 1080)");
    ( "-d",
      Arg.String
        (fun s ->
          match String.split_on_char ':' s with
          | [ host; port ] ->
              dial_addr := host;
              dial_port := port
          | _ -> failwith "bad dialing address, must be host:port"),
      "dial address" );
    ( "-k",
      Arg.Set_string identity_pub,
      "base64-encoded server signing public key" );
  ]

let load_identity path =
  let pem = In_channel.(with_open_text path input_all) in
  match X509.Public_key.decode_pem pem with
  | Ok (`ED25519 pub) -> pub
  | Error (`Msg msg) -> failwith msg
  | _ -> failwith @@ "failed loading server public key at " ^ path

let handle_conn net flow _addr ~signing_pubkey =
  Eio.Net.with_tcp_connect net ~host:!dial_addr ~service:!dial_port
  @@ fun remote_flow ->
  let wrapped_remote = Sockscaml.Client.handshake remote_flow ~signing_pubkey in
  Fiber.first
    (fun () -> Eio.Flow.copy flow wrapped_remote)
    (fun () -> Eio.Flow.copy wrapped_remote flow)

let main ~net =
  Switch.run ~name:"main" @@ fun sw ->
  let signing_pubkey = load_identity !identity_pub in
  let stop_p, stop_r = Promise.create () in
  Sys.(set_signal sigint (Signal_handle (fun _ -> Promise.resolve stop_r ())));
  let sockaddr = `Tcp (!listening_addr, !listening_port) in
  traceln "Dial to %s:%s" !dial_addr !dial_port;
  traceln "Listening on %a" Eio.Net.Sockaddr.pp sockaddr;
  Fiber.first (fun () -> Promise.await stop_p) @@ fun () ->
  let socket = Eio.Net.listen ~sw net sockaddr ~backlog:10 ~reuse_addr:true in
  Eio.Net.run_server socket
    (handle_conn net ~signing_pubkey)
    ~on_error:(traceln "%a" Eio.Exn.pp)

let () =
  let usage = "ss-client [-l addr] [-p port] -d addr:port -k identity.pub" in
  Arg.parse arg_spec ignore usage;
  if !dial_addr = "" then failwith "Dialing address must be specified";
  Mirage_crypto_rng_unix.use_default ();
  Eio_main.run @@ fun env -> main ~net:(Eio.Stdenv.net env)
