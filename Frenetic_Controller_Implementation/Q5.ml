(* Q5.ml
 *
 * This module performs as a router in a tree-form network with 3 switches and 4 hosts.
 * 
 * The packets are delived according to the destination MAC address.
 *
 * COUNTING is not implemented as informed.
 *
 * @author Chao CHEN
 * @UNI cc3736
 *)

open NetKAT.Std

let router : policy = 
    <:netkat<
      if switch = 1 then(
        if ( ethDst = 0x000000000001 || ethDst = 0x000000000002 ) then port := 1
        else if ( ethDst = 0x000000000003 || ethDst = 0x000000000004 ) then port := 2
        else drop
      )
      else if switch = 2 then(
        if ethDst = 0x000000000001 then port := 1
        else if ethDst = 0x000000000002 then port := 2
        else if ( ethDst = 0x000000000003 || ethDst = 0x000000000004 ) then port := 3
        else drop
      )
      else if switch = 3 then(
        if ethDst = 0x000000000003 then port := 1
        else if ethDst = 0x000000000004 then port := 2
        else if ( ethDst = 0x000000000001 || ethDst = 0x000000000002 ) then port := 3
        else drop
      )
      else drop
    >>

let _ = run_static router