(* Q3.ml
 *
 * This module produced by modification based on Q1
 * This module performs as a hub as well as as a kind of
 * firewall to block all the ssh request from h1 to h3 or h4,
 *
 * COUNTING is not implemented as informed.
 *
 * @author Chao CHEN
 * @UNI cc3736
 *)

open NetKAT.Std

let hub : policy = 
    <:netkat<
    	if port = 1 then port := 2 + port := 3 + port := 4
    	else if port = 2 then port := 1 + port := 3 + port := 4
    	else if port = 3 then port := 1 + port := 2 + port := 4
    	else if port = 4 then port := 1 + port := 2 + port := 3
    	else drop
    >>

let ssh_block : policy =
	<:netkat<
		if (ethType = 0x0800 && ethSrc = 0x000000000001 && ipProto = 0x06 && 
            tcpDstPort = 22 && (ethDst = 0x000000000003 || ethDst = 0x000000000004))
             then drop
		else $hub
	>>

let _ = run_static ssh_block
