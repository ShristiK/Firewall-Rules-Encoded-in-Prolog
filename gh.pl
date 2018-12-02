
/*First the syntax of packet is being checked. If the packet data is not according to syntax e.g. port number exceeds 65535 
then an error message is sent stating the reason of where the first occurence of error is encountered and the no rules are checked*/

/*list of adapter id possible*/
isl([1,2,3,4,5,6,7,8]).
/*any keyword is acceptable for all arguments if we want packet to be allowed irrespective of that arguement*/
isl2([any]).
/*pow function is used to specify IP Address*/
pow2(X,Y,Z):- Z is X**Y.


pop([X|L],X,L).

check_Adapter(X):-   isl(L),isl2(L2),not(member(X,L)),not(member(X,L2)),write('not correct adapter format').
check_Src(X):-       isl2(L2),not(member(X,L2)),pow2(2,32,Z),not(between(1,Z,X)),write('not correct src address').
check_Dest(X):-      isl2(L2),not(member(X,L2)),pow2(2,32,Z),not(between(1,Z,X)),write('not correct dest address').
check_Port(X):-      isl2(L2),not(member(X,L2)),not(between(0,65535,X)),write('not correct port no').
check_Proto(X):-     isl2(L2),not(member(X,L2)),not(between(1,255,X)),write('not correct protocol no').
check_Vlan(X):-      isl2(L2),not(member(X,L2)),not(between(1,4094,X)),write('not correct vlan id').
check_Icmp_Type(X):- isl2(L2),not(member(X,L2)),not(between(0,254,X)),write('not correct icmp type').
check_Icmp_Code(X):- isl2(L2),not(member(X,L2)),not(between(0,15,X)),write('not correct icmp code').
check(List):-        pop(List,AdapterNo,L1),not(check_Adapter(AdapterNo)),pop(L1,SrcAddress,L2),not(check_Src(SrcAddress)),pop(L2,DestAddress,L3),not(check_Dest(DestAddress)),pop(L3,PortNo,L4),not(check_Port(PortNo)),pop(L4,PortNo1,L5),not(check_Port(PortNo1)),pop(L5,ProtoNo,L6),not(check_Proto(ProtoNo)),pop(L6,VlanId,L7),not(check_Vlan(VlanId)),pop(L7,IcmpType,L8),not(check_Icmp_Type(IcmpType)),pop(L8,IcmpCode,L9),not(check_Icmp_Code(IcmpCode)).

%Code



proto_allow_list([1,6,17]).


src_port_droplist([12322,53241]).
src_port_drop_range(X):- (X>=45),(X =<90).
% Block if port is in range or src address or destination address in range.

dest_port_droplist([21,4,324,432]).
dest_port_drop_range(X) :- (X>= 22),(X=< 435).

src_ip_drop_list([6,9,11,13]).
dst_ip_drop_list([19,12,45,66]).
range_ip_src_drop(X):-(X>=56),(X=<78).
range_ip_dst_drop(X):-(X>=100),(X=<200).

ether_vlan_id_droplist([423,55,21]).
ether_vlan_id_drop_range(X):- (X>= 400, X=< 500).
ether_vlan_id_drop(X):- (ether_vlan_id_droplist(L),member(X,L));(ether_vlan_id_drop_range(X)).



ip_src_drop(X):-(src_ip_drop_list(L1),member(X,L1));range_ip_src_drop(X).

ip_dst_drop(X):-(dst_ip_drop_list(L2),member(X,L2));range_ip_dst_drop(X).

src_port_drop(X) :- (src_port_droplist(L),member(X,L));src_port_drop_range(X).

dest_port_drop(X):- (dest_port_droplist(M),member(X,M));dest_port_drop_range(X).

proto_drop(X):-not((any_list(R2),member(X,R2));(proto_allow_list(R1),member(X,R1))).

drop(X):-(


               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,D,L3),pop(L3,Po,L4),pop(L4,P1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9),ip_src_drop(SrcAddress));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,Po,L4),pop(L4,P1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9),ip_dst_drop(DestAddress));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,PortNo,L4),pop(L4,P1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9),src_port_drop(PortNo));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,PortNo,L4),pop(L4,PortNo1,L5),pop(L5,P,L6),pop(L6,V,L7),pop(L7,It,L8),pop(L8,Ic,L9), dest_port_drop(PortNo1));

               (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,PortNo,L4),pop(L4,PortNo1,L5),pop(L5,ProtoNo,L6), proto_drop(ProtoNo));

             (pop(X,AdapterNo,L1),pop(L1,SrcAddress,L2),pop(L2,DestAddress,L3),pop(L3,PortNo,L4),pop(L4,PortNo1,L5),pop(L5,ProtoNo,L6), pop(L6,vlanid,L7),ether_vlan_id_drop(vlanid))),write('packet is dropped(silently) due to ipv4.').

src_port_rejectlist([331,56,86,231]).
dest_port_rejectlist([674,344,7867]).

src_ip_reject_list([1,4]).
dst_ip_reject_list([129,212]).

src_port_reject_range(X):- (X>=21),(X=< 78).
dest_port_reject_range(X) :- (X>= 22),(X=< 435).
range_ip_src_reject(X):-(X>=158),(X=<178).
range_ip_dst_reject(X):-(X>=320),(X=<360).
icmp_type_reject_list([1,312,5]).
%icmp_code_reject_list([1,3,2]).

src_port_reject1(X) :- ((src_port_rejectlist(N),member(X,N));src_port_reject_range(X)),write('rejected due to source port due to ipv4').
dest_port_reject1(X):-((dest_port_rejectlist(O),member(X,O));dest_port_reject_range(X)),write('rejected due to destination port due to ipv4').

ip_src_reject1(X):-((src_ip_reject_list(P1),member(X,P1));range_ip_src_reject(X)),write('rejected due to source address due to ipv4').
ip_dst_reject1(X):-((dst_ip_reject_list(P2),member(X,P2));range_ip_dst_reject(X)),write('rejected due to destination address due to ipv4').


src_port_reject(X,Y,Z) :- ((src_port_rejectlist(N),member(X,N)); src_port_reject_range(X)),write('rejected due to source port due to ipv4'),((Y=:=0)->write('ICMP Type not declared');(write('ICMP Type:'),write( Y ),write(' ICMP Code:'), write(Z))).
dest_port_reject(X,Y,Z):- ((dest_port_rejectlist(O),member(X,O));dest_port_reject_range(X)) ,write('rejected due to destination port considering ipv4'),((Y=:=0)->write('ICMP Type not declared');(write('ICMP Type:'),write(Y),write(' ICMP Code:'),write(Z))).
ip_src_reject(X,Y,Z):-((src_ip_reject_list(P1),member(X,P1));range_ip_src_reject(X)),write('rejected due to source address considering ipv4 '),((Y=:=0)->write('ICMP Type not declared');(write('ICMP Type:'),write(Y),write( ' ICMP Code:'),write(Z))).
ip_dst_reject(X,Y,Z):-((dst_ip_reject_list(P2),member(X,P2));range_ip_dst_reject(X)),write('rejected due to destination address considering ipv4'),((Y=:=0)->write('ICMP Type not declared');(write('ICMP Type:'),write(Y),write(' ICMP Code:'),write(Z))).

icmp_reject(X,Y,Z):- (icmp_type_reject_list(L),member(X,L)),write('rejected due to icmp type considering ipv4'),((Y=:=0)->write('ICMP Type not declared');(write('ICMP Type:'),write(Y),write(' ICMP Code:'),write(Z))).


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


adaptlist([1,2,any]).

allow_due_to_adapter(X) :-  (pop(X,AdapterNo,L1),adaptlist(K),not(member(X,K))), write('allowed directly as adapter not doesnot match list of adapters').

%alllloooowww
packet(X):- (check(X), (allow_due_to_adapter(X); reject(X);drop(X);allow(X))).
%packet consition
%









