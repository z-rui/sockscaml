let key = String.init 32 Char.chr
let printhex = String.iter (fun c -> Printf.printf "%02x" (Char.code c))

let test_hchacha20 () =
  let nonce =
    "\x00\x00\x00\x09\x00\x00\x00\x4a\x00\x00\x00\x00\x31\x41\x59\x27"
  in
  let output = Chacha20.hchacha20 ~key ~nonce in
  Printf.printf "hchacha20: ";
  printhex output;
  Printf.printf "\n%!"

let test_chacha20 () =
  (* RFC7539 2.4.2 *)
  let nonce = "\x00\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00\x00" in
  let input =
    "Ladies and Gentlemen of the class of '99: If I could offer you only one \
     tip for the future, sunscreen would be it."
  in
  let input_size = String.length input in
  let buf = Bigstringaf.of_string input ~off:0 ~len:input_size in
  let cipher = Chacha20.create ~key ~nonce in
  Chacha20.set_counter cipher 1l;
  Chacha20.crypt cipher buf;
  print_string "chacha20: ";
  printhex (Bigstringaf.to_string buf);
  print_newline ()

let test_counter () =
  let nonce = String.make 12 '\x00' in
  let cipher = Chacha20.create ~key ~nonce in
  Printf.printf "test_counter: ";
  let c1 = Chacha20.get_counter cipher in
  if c1 <> 0l then failwith "initial counter should be 0";
  Chacha20.set_counter cipher 42l;
  let c2 = Chacha20.get_counter cipher in
  if c2 <> 42l then failwith "counter should be 42";

  (* Crypt 64 bytes should increment counter internally *)
  let buf = Bigstringaf.create 64 in
  Chacha20.crypt cipher buf;
  let c3 = Chacha20.get_counter cipher in
  if c3 <> 43l then failwith (Printf.sprintf "counter should be 43, got %ld" c3);
  Printf.printf "OK\n%!"

let test_overflow () =
  let nonce = String.make 12 '\x00' in
  let cipher = Chacha20.create ~key ~nonce in
  Printf.printf "test_overflow: ";

  (* Test overflow during crypt *)
  let buf = Bigstringaf.create 64 in
  Chacha20.set_counter cipher 0xFFFFFFFFl;
  begin try
    Chacha20.crypt cipher buf;
    failwith "crypt should raise CounterOverflow"
  with Chacha20.CounterOverflow -> ()
  end;
  Printf.printf "OK\n%!"

let () =
  test_hchacha20 ();
  test_chacha20 ();
  test_counter ();
  test_overflow ()
