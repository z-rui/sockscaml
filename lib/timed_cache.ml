module type S = sig
  type key
  type t

  val create : int -> ttl:float -> t
  val add : t -> key -> float -> bool
end

module Make (Key : Hashtbl.HashedType) : S with type key = Key.t = struct
  module Lookup = Hashtbl.Make (Key)

  type key = Key.t

  type t = {
    entries : (Key.t * float) Queue.t;
    lookup : unit Lookup.t;
    ttl : float;
  }

  let create sz ~ttl =
    { entries = Queue.create (); lookup = Lookup.create sz; ttl }

  let add t key now =
    let rec remove_expired () =
      match Queue.peek_opt t.entries with
      | Some (key, creation) when creation -. now >= t.ttl ->
          Lookup.remove t.lookup key;
          ignore (Queue.take t.entries);
          remove_expired ()
      | _ -> ()
    in
    remove_expired ();
    if Lookup.mem t.lookup key then false
    else begin
      Lookup.add t.lookup key ();
      Queue.add (key, now) t.entries;
      true
    end
end
