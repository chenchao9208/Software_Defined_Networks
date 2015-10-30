Name: Chao Chen
UNI: cc3736

Hw1Switch performs 3 functions:

1. Learning Switch.   Activated automatically.

2. Firewall.     Activated by configure one line on the top in Hw1Switch.java:
   
     protected boolean fireWallActivated = true; //Set to TRUE to activate firewall

3. Load Balance(Bonus). Activate by configure some lines on the top in Hw1Switch.java:
     
     protected boolean loadBalanceActivated= true; //Set to TRUE to activate load balance
     protected ArrayList<String[]> serverList=newArrayList<String[]>(){{
          add(new String[]{“10.0.0.2”,”0a:00:22:22:22:22”});
          add(new String[]{“10.0.0.3”,”0a:00:33:33:33:33”}); //add server with IP&MAC pair
     }}

   The pair of IP address and MAC address of each server should be saved correctly in the serverList structure.

   To perform load balance, first you should let the controller learn about MORE THAN ONE servers by whatever instructions such as (server1 PING server2), (host1 PING server3), CURL… and so on.

Comments and notes are added in Hw1Switch.java to help your understanding of the codes.


