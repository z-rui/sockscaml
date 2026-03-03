open Eio.Std

let run_server net listen_addr =
  Switch.run ~name:"Socks5.run_server" @@ fun sw ->
  let listening_socket = Eio.Net.listen ~sw net listen_addr ~backlog:10 in
  Eio.Net.run_server listening_socket (Socks5.handle_client net)
    ~on_error:(traceln "%a" Eio.Exn.pp)

let () =
  Eio_main.run @@ fun env ->
  let net = Eio.Stdenv.net env in
  run_server net (`Tcp (Eio.Net.Ipaddr.V4.any, 1080))
