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

let () =
  test_hchacha20 ();
  test_chacha20 ()
