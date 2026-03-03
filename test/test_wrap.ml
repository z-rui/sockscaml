let () =
  let input = Eio_mock.Flow.make "input" in
  Eio_mock.Flow.on_read input [ `Return "abcdefg"; `Return "OPQRSTU" ];
  let transform buf =
    let n = Cstruct.length buf in
    for i = 0 to n - 1 do
      let ch = Cstruct.get_byte buf i in
      Cstruct.set_uint8 buf i (ch lxor 0x20)
    done
  in
  let wrapped_flow =
    Sockscaml.Wrap.two_way ~read_processor:transform ~write_processor:transform
      input
  in
  Eio.Flow.read_all wrapped_flow |> print_endline
