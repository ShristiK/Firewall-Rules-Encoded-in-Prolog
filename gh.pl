
/*First the syntax of packet is being checked. If the packet data is not according to syntax e.g. port number exceeds 65535 
then an error message is sent stating the reason of where the first occurence of error is encountered and the no rules are checked*/

/*list of adapter id possible*/
isl([1,2,3,4,5,6,7,8]).

/*any keyword is acceptable for all arguments if we want packet to be allowed irrespective of that arguement*/
isl2([any]).

/*pow function is used to specify IP Address*/
pow2(X,Y,Z):- Z is X**Y.

/*pop is used to get arguments from the packet list*/
pop([X|L],X,L).

/* in built predicate between is used to check the range*/

check_Adapter(X):-   isl(L),isl2(L2),not(member(X,L)),not(member(X,L2)),write('not correct adapter format').  /*to check adapter id syntax,gives true for wrong syntax*/
check_Src(X):-       isl2(L2),not(member(X,L2)),pow2(2,32,Z),not(between(1,Z,X)),write('not correct src address').  /*to check source ip address syntax,gives true for wrong syntax */
check_Dest(X):-      isl2(L2),not(member(X,L2)),pow2(2,32,Z),not(between(1,Z,X)),write('not correct dest address').  /*to check destination ip address syntax,gives true for wrong syntax*/
check_Port(X):-      isl2(L2),not(member(X,L2)),not(between(0,65535,X)),write('not correct port no'). /*to check port number syntax,gives true for wrong syntax*/
check_Proto(X):-     isl2(L2),not(member(X,L2)),not(between(1,255,X)),write('not correct protocol no'). /*to check prtocol number syntax,gives true for wrong syntax*/
check_Vlan(X):-      isl2(L2),not(member(X,L2)),not(between(1,4094,X)),write('not correct vlan id'). /*to check VLan ID syntax,gives true for wrong syntax*/
check_Icmp_Type(X):- isl2(L2),not(member(X,L2)),not(between(0,254,X)),write('not correct icmp type'). /*to check icmp code syntax. If not mentioned,give 0,gives true for wrong syntax*/
check_Icmp_Code(X):- isl2(L2),not(member(X,L2)),not(between(0,15,X)),write('not correct icmp code'). /*to check icmp type syntax. If not mentioned,give 0,gives true for wrong syntax*/

/*if any of the syntax is false check(List) will return false. takes packet as argument*/
check(List):-        pop(List,AdapterNo,L1),not(check_Adapter(AdapterNo)),pop(L1,SrcAddress,L2),not(check_Src(SrcAddress)),pop(L2,DestAddress,L3),not(check_Dest(DestAddress)),pop(L3,PortNo,L4),not(check_Port(PortNo)),pop(L4,PortNo1,L5),not(check_Port(PortNo1)),pop(L5,ProtoNo,L6),not(check_Proto(ProtoNo)),pop(L6,VlanId,L7),not(check_Vlan(VlanId)),pop(L7,IcmpType,L8),not(check_Icmp_Type(IcmpType)),pop(L8,IcmpCode,L9),not(check_Icmp_Code(IcmpCode)).






proto_allow_list([1,6,17]).

/*-----------DROP arguments----------------*/

/* manually created lists to specify when to drop the packet. Values can be added or deleted but keep the list [] if don't want any arguements)*/

/* "port numbers / IP ADdresses/ether VLAN id" can lie in form of a list as well as in range. Both cases have been handled)*/

src_port_droplist([12322,53241]).                      /* list of  source port numbers */
dest_port_droplist([21,4,324,432]).                   /* list of destination port numbers */

src_port_drop_range(X):- (X>=45),(X =<90).            /* range of  source port numbers */
dest_port_drop_range(X) :- (X>= 22),(X=< 435).       /* range of destination port numbers */

src_ip_drop_list([6,9,11,13]).                       /* list of  source ip address */
dst_ip_drop_list([19,12,45,66]).                     /* list of  destination ip address */

range_ip_src_drop(X):-(X>=56),(X=<78).                /* range of  source ip address */
range_ip_dst_drop(X):-(X>=100),(X=<200).              /* range of destination ip address */

ether_vlan_id_droplist([423,55,21]).                  /*list of VLAN id */
ether_vlan_id_drop_range(X):- (X>= 400, X=< 500).       /* range of  VLAN id */


/*checks if packet should be dropped on basis of VLAN ID ,returns true if packet is dropped*/
ether_vlan_id_drop(X):- (ether_vlan_id_droplist(L),member(X,L));(ether_vlan_id_drop_range(X)).

/*checks if packet should be dropped on basis of source ip address,returns true if packet is dropped */
ip_src_drop(X):-(src_ip_drop_list(L1),member(X,L1));range_ip_src_drop(X).

/*checks if packet should be dropped on basis of destination ip address,returns true if packet is dropped */
ip_dst_drop(X):-(dst_ip_drop_list(L2),member(X,L2));range_ip_dst_drop(X).

/*checks if packet should be dropped on basis of source port number,returns true if packet is dropped */
src_port_drop(X) :- (src_port_droplist(L),member(X,L));src_port_drop_range(X).

/*checks if packet should be dropped on basis of destination ip address,returns true if packet is dropped */
dest_port_drop(X):- (dest_port_droplist(M),member(X,M));dest_port_drop_range(X).

/* protocol id if not TCP/UDP/ICMP, packet is dropped silently */
proto_drop(X):-not((any_list(R2),member(X,R2));(proto_allow_list(R1),member(X,R1))). 


/* A packet is dropped (silently) if any of the arguments satisfies the drop conditions. OR has been used to ensure this. If anyone is true drop(X) returns true i.e. packet is dropped*/
drop(X):-(


               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,D,L3),pop(L3,Po,L4),pop(L4,P1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9),ip_src_drop(SrcAddress));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,Po,L4),pop(L4,P1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9),ip_dst_drop(DestAddress));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,PortNo,L4),pop(L4,P1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9),src_port_drop(PortNo));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,PortNo,L4),pop(L4,PortNo1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9), dest_port_drop(PortNo1));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,PortNo,L4),pop(L4,PortNo1,L5),pop(L5,ProtoNo,L6), proto_drop(ProtoNo));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,PortNo,L4),pop(L4,PortNo1,L5),pop(L5,ProtoNo,L6), pop(L6,vlanid,L7),ether_vlan_id_drop(vlanid))),write('packet is dropped(silently) due to ipv4.').




/*-----------REJECT arguments----------------*/



/* manually created lists to specify when to reject the packet. Values can be added or deleted but keep the list [] even if you don't want any arguements)*/
/* assumed if protocol not TCP,UDP,ICMP it is dropped so we have not handled reject for protocol*/
/*only rejected on basis of ICMP, so ICMP case only handled for Reject and not dropped*/
/*ether VLANid is just handled to drop the packet and not reject the packet as given in syntax*/ (point 6 in readme file)
/* "port numbers / IP ADdresses/ether VLAN id" can lie in form of a list as well as in range. Both cases have been handled)*/

src_port_rejectlist([331,56,86,231]).                      /* list of  source port numbers */
dest_port_rejectlist([674,344,7867]).                      /* list of destination port numbers */

src_ip_reject_list([1,4]).                                /* list of  source ip address */
dst_ip_reject_list([129,212]).                            /* list of  destination ip address */

src_port_reject_range(X):- (X>=21),(X=< 78).              /* range of  source port numbers */
dest_port_reject_range(X) :- (X>= 22),(X=< 435).          /* range of destination port numbers */

range_ip_src_reject(X):-(X>=158),(X=<178).                /* range of destination ip address */
range_ip_dst_reject(X):-(X>=320),(X=<360).

icmp_type_reject_list([1,312,5]).                         /*icmp type to be rejected*/
%icmp_code_reject_list([1,3,2]).                          /*icmp code to be rejected*/

/* this predicate is later used to check if packet should be allowed (not used here in reject)*/
src_port_reject1(X) :- ((src_port_rejectlist(N),member(X,N));src_port_reject_range(X)),write('rejected due to source port due to ipv4').

/* this predicate is later used to check if packet should be allowed (not used here in reject)*/
dest_port_reject1(X):-((dest_port_rejectlist(O),member(X,O));dest_port_reject_range(X)),write('rejected due to destination port due to ipv4').

/* this predicate is later used to check if packet should be allowed (not used here in reject)*/
ip_src_reject1(X):-((src_ip_reject_list(P1),member(X,P1));range_ip_src_reject(X)),write('rejected due to source address due to ipv4').

/* this predicate is later used to check if packet should be allowed (not used here in reject)*/
ip_dst_reject1(X):-((dst_ip_reject_list(P2),member(X,P2));range_ip_dst_reject(X)),write('rejected due to destination address due to ipv4').

/*checks if packet should be rejected on basis of source port number ,returns true if packet is rejected...takes ICMP code as argument and if it is 0 then packet is simply rejected, otherwise icmp code is displayed*/
src_port_reject(X,Y,Z) :- ((src_port_rejectlist(N),member(X,N)); src_port_reject_range(X)),write('rejected due to source port due to ipv4'),((Y=:=0)->write('ICMP Type not declared');(write('ICMP Type:'),write( Y ),write(' ICMP Code:'), write(Z))).

/*checks if packet should be rejected on basis of destination port number ,returns true if packet is rejected and diplays reason to reject*/
dest_port_reject(X,Y,Z):- ((dest_port_rejectlist(O),member(X,O));dest_port_reject_range(X)) ,write('rejected due to destination port considering ipv4'),((Y=:=0)->write('ICMP Type not declared');(write('ICMP Type:'),write(Y),write(' ICMP Code:'),write(Z))).

/*checks if packet should be rejected on basis of source ip address ,returns true if packet is rejected and diplays reason to reject*/
ip_src_reject(X,Y,Z):-((src_ip_reject_list(P1),member(X,P1));range_ip_src_reject(X)),write('rejected due to source address considering ipv4 '),((Y=:=0)->write('ICMP Type not declared');(write('ICMP Type:'),write(Y),write( ' ICMP Code:'),write(Z))).

/*checks if packet should be rejected on basis of destination ip address ,returns true if packet is rejected and diplays reason to reject*/
ip_dst_reject(X,Y,Z):-((dst_ip_reject_list(P2),member(X,P2));range_ip_dst_reject(X)),write('rejected due to destination address considering ipv4'),((Y=:=0)->write('ICMP Type not declared');(write('ICMP Type:'),write(Y),write(' ICMP Code:'),write(Z))).

/*checks if packet should be rejected on basis of icmp type ,returns true if packet is rejected and diplays reason to reject*/
icmp_reject(X,Y,Z):- (icmp_type_reject_list(L),member(X,L)),write('rejected due to icmp type considering ipv4'),((Y=:=0)->write('ICMP Type not declared');(write('ICMP Type:'),write(Y),write(' ICMP Code:'),write(Z))).

/* A packet is rejected if any of the arguments satisfies the reject conditions. OR has been used to ensure this.
If anyone is true rejectX) returns true i.e. packet is rejected.  
If ICMP is 0 message displayed is NO ICMP DECLARED along with reason for reject, otherwise ICMP Code is also printed*/

reject(X):-(
                (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,D,L3),pop(L3,Po,L4),pop(L4,P1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9), icmp_reject(It,It,Ic));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,D,L3),pop(L3,Po,L4),pop(L4,P1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9),ip_src_reject(SrcAddress,It,Ic));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,Po,L4),pop(L4,P1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9),ip_dst_reject(DestAddress,It,Ic));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,PortNo,L4),pop(L4,P1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9),src_port_reject(PortNo,It,Ic));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,PortNo,L4),pop(L4,PortNo1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9), dest_port_reject(PortNo1,It,Ic))
           ).








ether_vlan_id_allowlist([423,55,21]).
ether_vlan_id_allow_range(X):- (X>= 400, X=< 500).
ether_vlan_id_allow(X):- (ether_vlan_id_allowlist(L),member(X,L));(ether_vlan_id_allow_range(X)).



proto_allow(X):-(any_list(R2),member(X,R2));(proto_allow_list(R1),member(X,R1)).

ip_src_allow(X):-(any_list(Q),member(X,Q));(not(ip_src_drop(X)),not(ip_src_reject1(X))).
ip_dst_allow(X):-(any_list(Q),member(X,Q));(not(ip_dst_drop(X)),not(ip_dst_reject1(X))).

any_list([any]).
src_port_allow(X):-(any_list(P),member(X,P));(not(src_port_drop(X)),not(src_port_reject1(X))).


dest_port_allow(X):- (any_list(Q),member(X,Q));(not(dest_port_drop(X)),not(dest_port_reject1(X))).

allow(X):-(


               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,D,L3),pop(L3,Po,L4),pop(L4,P1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9),ip_src_allow(SrcAddress));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,Po,L4),pop(L4,P1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9),ip_dst_allow(DestAddress));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,PortNo,L4),pop(L4,P1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9),src_port_allow(PortNo));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,PortNo,L4),pop(L4,PortNo1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9), dest_port_allow(PortNo1));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,PortNo,L4),pop(L4,PortNo1,L5),pop(L5,ProtoNo,L6), proto_allow(ProtoNo));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,PortNo,L4),pop(L4,PortNo1,L5),pop(L5,ProtoNo,L6), pop(L6,vlanid,L7),ether_vlan_id_allow(vlanid))),write('packet is allowed due to ipv4.').


/* If adapter of the packet is not in the list of allowed adapters the rules are not applied and the packet is allowed by default.*/

adaptlist([1,2,any]).
allow_due_to_adapter(X) :-  (pop(X,AdapterNo,L1),adaptlist(K),not(member(X,K))), write('allowed directly as adapter not doesnot match list of adapters').

packet(X):- (check(X), (allow_due_to_adapter(X); reject(X);drop(X);allow(X))).
/*
For checking ipv6 packet call the above predicates withh _ipv6. All rules of above are same. Only in check it checks the adress is in between 1 to 2**128 instead of 2**32 as was for ipv4.
*/

isl_ipv6([1,2,3,4,5,6,7,8]).
isl2_ipv6([any]).

check_Adapter_ipv6(X):-   isl_ipv6(L),isl2_ipv6(L2),not(member(X,L)),not(member(X,L2)),write('not correct adapter format').
check_Src_ipv6(X):-       isl2_ipv6(L2),not(member(X,L2)),pow2(2,128,Z),not(between(1,Z,X)),write('not correct src address').
check_Dest_ipv6(X):-      isl2_ipv6(L2),not(member(X,L2)),pow2(2,128,Z),not(between(1,Z,X)),write('not correct dest address').
check_Port_ipv6(X):-      isl2_ipv6(L2),not(member(X,L2)),not(between(0,65535,X)),write('not correct port no').
check_Proto_ipv6(X):-     isl2_ipv6(L2),not(member(X,L2)),not(between(1,255,X)),write('not correct protocol no').
check_Vlan_ipv6(X):-      isl2_ipv6(L2),not(member(X,L2)),not(between(1,4094,X)),write('not correct vlan id').
check_Icmp_Type_ipv6(X):- isl2_ipv6(L2),not(member(X,L2)),not(between(0,254,X)),write('not correct icmp type').
check_Icmp_Code_ipv6(X):- isl2_ipv6(L2),not(member(X,L2)),not(between(0,15,X)),write('not correct icmp code').
check_ipv6(List):-        pop(List,AdapterNo,L1),not(check_Adapter_ipv6(AdapterNo)),pop(L1,SrcAddress,L2),not(check_Src_ipv6(SrcAddress)),pop(L2,DestAddress,L3),not(check_Dest_ipv6(DestAddress)),pop(L3,PortNo,L4),not(check_Port_ipv6(PortNo)),pop(L4,PortNo1,L5),not(check_Port_ipv6(PortNo1)),pop(L5,ProtoNo,L6),not(check_Proto_ipv6(ProtoNo)),pop(L6,VlanId,L7),not(check_Vlan_ipv6(VlanId)),pop(L7,IcmpType,L8),not(check_Icmp_Type_ipv6(IcmpType)),pop(L8,IcmpCode,L9),not(check_Icmp_Code_ipv6(IcmpCode)).


src_port_droplist_ipv6([12322,53241]).
src_port_drop_range_ipv6(X):- (X>=45),(X =<90).
% Block if port is in range or src address or destination address in range.

dest_port_droplist_ipv6([21,4,324,432]).
dest_port_drop_range_ipv6(X) :- (X>= 22),(X=< 435).

src_ip_drop_list_ipv6([6,9,11,13]).
dst_ip_drop_list_ipv6([19,12,45,66]).
range_src_ip_drop_ipv6(X):-(X>=56),(X=<78).
range_dst_ip_drop_ipv6(X):-(X>=100),(X=<200).

ether_vlan_id_droplist_ipv6([423,55,21]).
ether_vlan_id_drop_range_ipv6(X):- (X>= 400, X=< 500).
ether_vlan_id_drop_ipv6(X):- (ether_vlan_id_droplist_ipv6(L),member(X,L));(ether_vlan_id_drop_range_ipv6(X)).

proto_allow_list_ipv6([1,6,17]).


src_ip_drop_ipv6(X):-(src_ip_drop_list_ipv6(L1),member(X,L1));range_src_ip_drop_ipv6(X).

dst_ip_drop_ipv6(X):-(dst_ip_drop_list_ipv6(L2),member(X,L2));range_dst_ip_drop_ipv6(X).

src_port_drop_ipv6(X) :- (src_port_droplist_ipv6(L),member(X,L));src_port_drop_range_ipv6(X).

dest_port_drop_ipv6(X):- (dest_port_droplist_ipv6(M),member(X,M));dest_port_drop_range_ipv6(X).

proto_drop_ipv6(X):-not((any_list(R2),member(X,R2));(proto_allow_list_ipv6(R1),member(X,R1))).

drop_ipv6(X):-(


               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,D,L3),pop(L3,Po,L4),pop(L4,P1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9),src_ip_drop_ipv6(SrcAddress));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,Po,L4),pop(L4,P1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9),dst_ip_drop_ipv6(DestAddress));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,PortNo,L4),pop(L4,P1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9),src_port_drop_ipv6(PortNo));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,PortNo,L4),pop(L4,PortNo1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9), dest_port_drop_ipv6(PortNo1));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,PortNo,L4),pop(L4,PortNo1,L5),pop(L5,ProtoNo,L6), proto_drop_ipv6(ProtoNo));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,PortNo,L4),pop(L4,PortNo1,L5),pop(L5,ProtoNo,L6), pop(L6,vlanid,L7),ether_vlan_id_drop_ipv6(vlanid))),write('packet is dropped(silently) due to ipv4.').




src_port_rejectlist_ipv6([331,56,86,231]).
dest_port_rejectlist_ipv6([674,344,7867]).

src_ip_reject_list_ipv6([1,4]).
dst_ip_reject_list_ipv6([129,212]).

src_port_reject_range_ipv6(X):- (X>=21),(X=< 78).
dest_port_reject_range_ipv6(X) :- (X>= 22),(X=< 435).
range_src_ip_reject_ipv6(X):-(X>=158),(X=<178).
range_dst_ip_reject_ipv6(X):-(X>=320),(X=<360).
icmp_type_reject_list_ipv6([1,312,5]).
%icmp_code_reject_list([1,3,2]).

src_port_reject1_ipv6(X) :- ((src_port_rejectlist_ipv6(N),member(X,N));src_port_reject_range_ipv6(X)),write('rejected due to source port due to ipv6').
dest_port_reject1_ipv6(X):-((dest_port_rejectlist_ipv6(O),member(X,O));dest_port_reject_range_ipv6(X)),write('rejected due to destination port due to ipv6').

src_ip_reject1_ipv6(X):-((src_ip_reject_list_ipv6(P1),member(X,P1));range_src_ip_reject_ipv6(X)),write('rejected due to source address due to ipv6').
dst_ip_reject1_ipv6(X):-((dst_ip_reject_list_ipv6(P2),member(X,P2));range_dst_ip_reject_ipv6(X)),write('rejected due to destination address due to ipv6').


src_port_reject_ipv6(X,Y,Z) :- ((src_port_rejectlist_ipv6(N),member(X,N)); src_port_reject_range_ipv6(X)),write('rejected due to source port due to ipv6'),((Y=:=0)->write('ICMP Type not declared');(write('ICMP Type:'),write( Y ),write(' ICMP Code:'), write(Z))).
dest_port_reject_ipv6(X,Y,Z):- ((dest_port_rejectlist_ipv6(O),member(X,O));dest_port_reject_range_ipv6(X)) ,write('rejected due to destination port considering ipv4'),((Y=:=0)->write('ICMP Type not declared');(write('ICMP Type:'),write(Y),write(' ICMP Code:'),write(Z))).
src_ip_reject_ipv6(X,Y,Z):-((src_ip_reject_list_ipv6(P1),member(X,P1));range_src_ip_reject_ipv6(X)),write('rejected due to source address considering ipv4 '),((Y=:=0)->write('ICMP Type not declared');(write('ICMP Type:'),write(Y),write( ' ICMP Code:'),write(Z))).
dst_ip_reject_ipv6(X,Y,Z):-((dst_ip_reject_list_ipv6(P2),member(X,P2));range_dst_ip_reject_ipv6(X)),write('rejected due to destination address considering ipv4'),((Y=:=0)->write('ICMP Type not declared');(write('ICMP Type:'),write(Y),write(' ICMP Code:'),write(Z))).

icmp_reject_ipv6(X,Y,Z):- (icmp_type_reject_list_ipv6(L),member(X,L)),write('rejected due to icmp type considering ipv4'),((Y=:=0)->write('ICMP Type not declared');(write('ICMP Type:'),write(Y),write(' ICMP Code:'),write(Z))).



reject_ipv6(X):-(
                (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,D,L3),pop(L3,Po,L4),pop(L4,P1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9), icmp_reject_ipv6(It,It,Ic));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,D,L3),pop(L3,Po,L4),pop(L4,P1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9),src_ip_reject_ipv6(SrcAddress,It,Ic));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,Po,L4),pop(L4,P1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9),dst_ip_reject_ipv6(DestAddress,It,Ic));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,PortNo,L4),pop(L4,P1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9),src_port_reject_ipv6(PortNo,It,Ic));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,PortNo,L4),pop(L4,PortNo1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9), dest_port_reject_ipv6(PortNo1,It,Ic))
           ).


ether_vlan_id_allowlist_ipv6([423,55,21]).
ether_vlan_id_allow_range_ipv6(X):- (X>= 400, X=< 500).
ether_vlan_id_allow_ipv6(X):- (ether_vlan_id_allowlist_ipv6(L),member(X,L));(ether_vlan_id_allow_range_ipv6(X)).



proto_allow_ipv6(X):-(any_list(R2),member(X,R2));(proto_allow_list_ipv6(R1),member(X,R1)).


src_ip_allow_ipv6(X):-(any_list(Q),member(X,Q));(not(src_ip_drop_ipv6(X)),not(src_ip_reject1_ipv6(X))).
dst_ip_allow_ipv6(X):-(any_list(Q),member(X,Q));(not(dst_ip_drop_ipv6(X)),not(dst_ip_reject1_ipv6(X))).

any_list_ipv6([any]).
src_port_allow_ipv6(X):-(any_list_ipv6(P),member(X,P));(not(src_port_drop_ipv6(X)),not(src_port_reject1_ipv6(X))).


dest_port_allow_ipv6(X):- (any_list(Q),member(X,Q));(not(dest_port_drop_ipv6(X)),not(dest_port_reject1_ipv6(X))).

allow_ipv6(X):-(


               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,D,L3),pop(L3,Po,L4),pop(L4,P1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9),src_ip_allow_ipv6(SrcAddress));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,Po,L4),pop(L4,P1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9),dst_ip_allow_ipv6(DestAddress));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,PortNo,L4),pop(L4,P1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9),src_port_allow_ipv6(PortNo));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,PortNo,L4),pop(L4,PortNo1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9), dest_port_allow_ipv6(PortNo1));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,PortNo,L4),pop(L4,PortNo1,L5),pop(L5,ProtoNo,L6), proto_allow_ipv6(ProtoNo));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,PortNo,L4),pop(L4,PortNo1,L5),pop(L5,ProtoNo,L6), pop(L6,vlanid,L7),ether_vlan_id_allow_ipv6(vlanid))),write('packet is allowed due to ipv4.').


adaptlist_ipv6([1,2,any]).

allow_due_to_adapter_ipv6(X) :-  (pop(X,AdapterNo,L1),adaptlist_ipv6(K),not(member(X,K))), write('allowed directly as adapter not doesnot match list of adapters').




packet_ipv6(X):- (check_ipv6(X), (allow_due_to_adapter_ipv6(X); reject_ipv6(X);drop_ipv6(X);allow_ipv6(X))).








