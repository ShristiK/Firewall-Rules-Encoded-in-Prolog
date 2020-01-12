# Firewall Rules Encoded in Predicate Logic
<p align="center"> <b>Shristi Kumari(BITS Pilani)</b> </p>

The aim of this Project is to encode Firewall Rules using Predicate Logic. **SWI-Prolog**; a software implementation of prolog has been used for the coding part.

# Introduction

Firewall Rules examine the control information in individual packets. The Rules either block or allow those packets based on the rules that have been defined. A firewall rule consists of several clauses chained together to match specific criteria for each packet. The clauses represent specific layers in the protocol stack. Each clause can be broken down into conditions and expressions. The expressions are the variable part of the rule in which one can put the address, port, or numeric parameters.


## Prolog and Logic Programming

Prolog is a Logic Programming Language associated with **Artificial Intelligence** and **Computational Linguistics**. Logic programming is a type of programming paradigm which is largely based on formal logic. Any program written in a logic programming language is a set of sentences in logical form, expressing facts and rules about some problem domain.

# Data and Software Used

The firewall rules encoded in this project is available in the Rules and Syntax folder. 
SWI-Prolog is a freely downloadable software available at https://www.swi-prolog.org/Download.html.

# Assumptions

1. The packet input is checked according to the given firewall rules.

----> Reject overrides "Drop" and "Drop" overrides "Allow".

----> Message displayed when packet is allowed/dropped/rejected :

   a. Allow: "Packet is Allowed."
   
   b. Drop : "Packet is Dropped" without giving any reason as dropped silently.
    
   c. Rejected: "Packet is rejected" along with the reason.

2. Within Reject/Allow/Deny, it has been assumed that packet is rejected/allowed/dropped even when one condition matches.
	i.e. If Source IP Address meets the reject condition, packet is dropped irrespective of other arguments of packet.

3. First input is checked for syntax error and if error is there it displays the first occurence of error.
 e.g. if ip address is given negative message displayed will be "not correct ip address".
 
---->for ipv4 range of ipaddress 1: 2^32

---->for ipv6 range of ipaddress 1: 2^128

---->for adapter id range = 1: 8

---->for adapter id range = 1: 8

---->for port no. range = 0: 65535

---->for protocol no. range = 1: 255

---->for VLan id range = 1: 4094

---->for icmp type range = 1: 255 (if no icmp, mention 0)

---->for icmp code range = 1: 15  (if no icmp, mention 0)

4. IP Addresses are given in just Decimal Format (IT IS ASSUMED PACKET HAS ALREADY IP ADDRESSES CONVERTED TO DECIMAL)

5. If the adapter of the packet doesn't match the adapt_list then no rules are applied on packet and it is allowed by default. If 'any' keyword is given in adapter paramter in packet, it means rules will be applied on the packet.  

6. VLan id is just checked for allowed and deny(dropped) as mentioned in firewall clause syntax.

7. If ICMP is not given in packet (i.e. ICMP code is set to 0) then reject message is displayed which says ICMP type not declared else reject message is displayed with ICMP Code and type provided.

8. Protocol allowed are only TCP,UDP,ICMP. Rest of them are dropped (silently)(not rejected). Protocol Id is given just in decimal form and not string.

9. If packet has both TCP/UDP and ICMP just declare TCP/UDP protocol number and give ICMP code and type not equal to 0.

10. Adapter ID has been mapped from A-H to 1-8.

11. IP Address are mapped to decimal numbers 1 to 2^32 for ipV4 and 1 to 2^128 for ipV6.

12. ICMP code if matches the ICMP reject list, the packet is rejected with message stating icmp code and type.+

# Input Format and Run Command
Input is assumed to be given as a specific format as follows:
  
---> A list of the form : 

['adapter id', 'ip source address', 'ip destination address', 'source port number', 'destination port number', 'protocol id' 'VLan id', 'ICMP code','ICMP type']
  
---> Each argument is in decimal.

---> In case we want to allow packet for any value of a particular parameter, give 'any' keyword. For e.g  if we want to allow packet from any source port, change the source port number to 'any'.
       
---> For ICMP code, if packet does not have icmp protocol then put ICMP Code as 0 and ICMP type as 0. If it does, ICMP code and type are given accordingly.

**Run Commands** 

```FOR IPV6 : USE PACKET_IPV6()```

```FOR IPV4 : USE PACKET()```



# Sample Test Cases

1. **Input:** packet([1,4,432,6,6,6,7,0,0)

   **Output:** rejected due to source address considering ipv4. ICMP type not declared.

   **Explanation:** Since 4 lies in list of rejected source ip addresses the packet is rejected. IPV4 rules are used since  packet() predicate is used. 
ICMP code is given 0 so icmp not declared comes.


2. **Input:** packet_ipv6([1,4,432,6,6,6,7,0,0)

   **Output:** rejected due to source address considering ipv4. ICMP type not declared.

   **Explanation:** Since 4 lies in list of rejected source ip addresses the packet is rejected. IPV6 rules are used since  packet_ipv6() predicate is used. 
ICMP code is given 0 so icmp not declared comes.


3. **Input:** packet_ipv6([1,3,432,6,6,6,7,0,0)

   **Output:** allowed due to source address considering ipv6. ICMP type not declared.

   **Explanation:** Since 4 doesnt lie in list of rejected as well as drop source ip addresses the packet is rejected. IPV6 rules are used since  packet() predicate is used. 
ICMP code is given 0 so icmp not declared comes.


4. **Input:** packet([1,4,432,6,6,6,7,1,1)

   **Output:** rejected due to icmp type considering ipv4. ICMP Type:1 ICMP Code:1

   **Explanation:** Since 4 lies in list of rejected source ip addresses the packet is rejected. IPV4 rules are used since  packet() predicate is used. 
ICMP code is given 1 so icmp code comes.


