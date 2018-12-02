		                                	INSTRUCTIONS

1. The packet input is checked according to the given firewall rules. 
----> Reject overrides "Drop" and "Drop" overrides "Allow".
----> Message displayed when packet is allowed/dropped/rejected :
   a. Allow: "Packet is Allowed."
   b. Drop : It is given the packet is dropped silently so we just give the message that "packet is dropped" without giving the reason.
    c. Rejected: "Packet is rejected" along with the reason.
----> After message is displayed press enter to terminate the code.

2. Within Reject/Allow/Deny, it has been assumed that packet is rejected/allowed/dropped even when one condition matches.
	i.e. If Source IP Address meets the reject condition, packet is dropped irrespective of other arguments of packet.

3. First input is checked for syntax error and if error is there it displays the first occurence of error.
 e.g. if ip address is given negative message displayed will be "not correct ip address".

4. IP Addresses are given in just Decimal Format (IT IS ASSUMED PACKET HAS ALREADY IP ADDRESSES CONVERTED TO DECIMAL)

5. If the adapter of the packet doesn't match the adapt_list then no rules are applied on packet and it is allowed by default.If 'any' keyword is given in adapter paramter in packet, it means rules will be applied on the packet.  

6. VLan id is just checked for allowed and deny(dropped) as mentioned in firewall clause syntax.

7. If ICMP is not given in packet (i.e. ICMP code is set to 0) then reject message displayed says ICMP type not declared else reject message is displayed with ICMP Code and type provided.

8. Protocol allowed are only TCP,UDP,ICMP. Rest of them are dropped (silently). Protocol Id is given just in decimal form and not string.

9. If packet has both TCP/UDP and ICMP just declare TCP/UDP protocol number and give ICMP code and type not equal to 0.

10. Adapter ID has been mapped from A-H to 1-8.

11. IP Address are mapped to decimal numbers 1 to 2^32 for ipV4 and 1 to 2^128 for ipV6.
