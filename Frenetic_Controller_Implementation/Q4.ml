(* Q4.ml
 *
 * This module produced by modification based on NetKATLearning.ml module provided in /home/frenetic/tutorials/live
 * The former module has only the function of learning switch.
 * This module combine the functions of firewall and learning switch.
 *
 * COUNTING is not implemented as informed.
 *
 * @author Chao CHEN
 * @UNI cc3736
 *)

open Core.Std
open Async.Std
open Async_NetKAT
open NetKAT_Types
open NetKAT.Std
open Packet

(* The hash table structure used to store the information of switch, destination mac address and the outport*)
let host_list : (switchId * dlAddr, portId) Hashtbl.t = 
  Hashtbl.Poly.create ()

(* The method to learn from the source MAC address from packet.
 * If the source MAC address has not been recorded, it will be put into the hash table.
 *
 * @return FALSE if the source MAC address has been recorded previously
 *        TRUE if the source MAC is new to the network
 *)
let learn (sw : switchId) (pt : portId) (pk : packet) : bool =
  match Hashtbl.find host_list (sw, pk.dlSrc) with
    | Some pt' when pt = pt' -> 
       false
    | _ -> 
       ignore (Hashtbl.add host_list (sw, pk.dlSrc) pt); 
       true

(* The method to decide how to output the packet
 * @return action of output with corresponding port 
 *)
let packet_out (sw : switchId) (pk : packet) : action =
    match Hashtbl.find host_list (sw, pk.dlDst) with
      | Some pt -> Output (Physical pt)
      | None -> Output All

let default = 
  <:netkat<port := "Q4">>

let learn_pol () = 
  List.fold_right
    (Hashtbl.to_alist host_list)
    ~init:default
    ~f:(fun ((sw,addr),pt) pol -> 
    <:netkat< 
          if switch = $sw && ethSrc = $addr then drop else $pol
    >>)

(* The method to decide a routing policy.
 * The firewall function is implemented here
 * If the packet is not allowed. The packet will be dropped. Else, it will output to the corresponding port.
 * @return a <netkat>structure which contains the match and action information
 *)
let route_pol () =
  List.fold_right
    (Hashtbl.to_alist host_list) 
    ~init:default
    ~f:(fun ((sw,addr),pt) pol -> 
      <:netkat<
        if  ethType = 0x0800 && ipProto = 0x06 && tcpDstPort = 443 &&
            (ethSrc = 0x000000000001 || ethSrc = 0x000000000002 || ethSrc = 0x000000000003)
            && (ethDst = 0x000000000001 || ethDst = 0x000000000002 || ethDst = 0x000000000003)
             then drop
        else if switch = $sw && ethDst = $addr then port := $pt
        else $pol
      >>)

let policy () = 
  let l = learn_pol () in 
  let r = route_pol () in 
  <:netkat< $l + $r >>

let handler t w () e = match e with
  | PacketIn(_, switch_id, port_id, payload, _) ->
    let packet = Packet.parse (SDN_Types.payload_bytes payload) in
    let pol = 
      if learn switch_id port_id packet then        
    Some (policy ())
      else
    None in
    let action = packet_out switch_id packet in
    (* If the packet is to be dropped, the action list will be set as empty*)
    if  dlTyp packet = 0x0800 && nwProto packet = 0x06 && tpDst packet = 443 &&
        ( packet.dlSrc = Int64.of_int 0x000000000001 || packet.dlSrc = Int64.of_int 0x000000000002 
        || packet.dlSrc = Int64.of_int 0x000000000003 )
        && ( packet.dlDst = Int64.of_int 0x000000000001 || packet.dlDst = Int64.of_int 0x000000000002
        || packet.dlDst = Int64.of_int 0x000000000003 ) then
          (  Pipe.write w (switch_id, (payload, Some(port_id), [])) >>= fun _ -> return pol)
    else (  Pipe.write w (switch_id, (payload, Some(port_id), [action])) >>= fun _ -> return pol)
  | _ -> return None

let _ =
  Async_NetKAT_Controller.start 
    (create ~pipes:(PipeSet.singleton "Q4") (policy ()) handler) ();
  never_returns (Scheduler.go ())
