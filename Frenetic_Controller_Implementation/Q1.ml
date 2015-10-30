(* Q1.ml
 *
 * This module produced based on materials in tutorial.
 * This module introduces the function of hub.
 *	Any packet sent to the switch will be delivered to all other ports except from the inport.
 * 
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

let _ = run_static hub

