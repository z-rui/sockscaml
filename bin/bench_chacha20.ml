let[@inline] xorshift x0 =
  let open Int32 in
  let x1 = logxor x0 (shift_left x0 13) in
  let x2 = logxor x1 (shift_right_logical x1 17) in
  let x3 = logxor x2 (shift_left x2 5) in
  x3

let hex_of_string s =
  String.to_seq s
  |> Seq.map (fun c -> Printf.sprintf "%02x" (Char.code c))
  |> List.of_seq |> String.concat ""

let bench_chacha20 () =
  let bench_size = 256 * 1024 * 1024 in
  let key = String.init Chacha20.key_size Char.chr in
  let nonce = "\x00\x00\x00\x4a\x00\x00\x00\x00\x31\x41\x59\x27" in
  let rng = ref 1l in
  let input = Bigstringaf.create bench_size in
  for i = 0 to bench_size - 1 do
    let next = xorshift !rng in
    rng := next;
    Bigstringaf.unsafe_set input i
      (Char.unsafe_chr (Int32.to_int next land 0xff))
  done;
  Printf.eprintf "bench chacha20 %d\n" bench_size;
  Printf.eprintf "first 10 bytes: %s\n"
    (Bigstringaf.substring input ~off:0 ~len:10 |> hex_of_string);
  Printf.eprintf "md5 before: %s\n%!"
    (Digest.MD5.string (Bigstringaf.to_string input) |> hex_of_string);
  let start_time = Sys.time () in
  let cipher = Chacha20.create ~key ~nonce in
  Chacha20.crypt cipher input;
  let end_time = Sys.time () in
  let duration = end_time -. start_time in
  let throughput = Float.of_int bench_size *. 1e-6 /. duration in
  Printf.eprintf "%.3f seconds - %.1f MB/s\n" duration throughput;
  Printf.eprintf "md5 after: %s\n"
    (Digest.MD5.string (Bigstringaf.to_string input) |> hex_of_string)

let () = bench_chacha20 ()
