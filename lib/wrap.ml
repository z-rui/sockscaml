open Eio.Std

type processor = Cstruct.t -> unit

let two_way ~(read_processor : processor) ~(write_processor : processor) flow =
  let ops =
    Eio.Flow.Pi.two_way
      (module struct
        type t = Eio.Flow.two_way_ty r

        let read_methods = []

        let single_read t buf =
          let n = Eio.Flow.single_read t buf in
          read_processor (Cstruct.sub buf 0 n);
          n

        let single_write t bufs =
          let total_bytes =
            List.fold_left
              (fun acc buf ->
                write_processor buf;
                acc + Cstruct.length buf)
              0 bufs
          in
          Eio.Flow.write t bufs;
          total_bytes

        let copy t ~src = Eio.Flow.Pi.simple_copy ~single_write t ~src
        let shutdown t cmd = Eio.Flow.shutdown t cmd
      end)
  in
  Eio.Resource.T ((flow :> Eio.Flow.two_way_ty r), ops)
