
/*list of adapter id possible*/
isl([1,2,3,4,5,6,7,8]).

/*any keyword is acceptable for all arguments if we want packet to be allowed irrespective of that arguement*/
isl2([any]).


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




/*-----------REJECT arguments----------------*/
src_port_rejectlist([331,56,86,231]).                      /* list of  source port numbers */
dest_port_rejectlist([674,344,7867]).                      /* list of destination port numbers */

src_ip_reject_list([1,4]).                                /* list of  source ip address */
dst_ip_reject_list([129,212]).                            /* list of  destination ip address */

src_port_reject_range(X):- (X>=21),(X=< 78).              /* range of  source port numbers */
dest_port_reject_range(X) :- (X>= 22),(X=< 435).          /* range of destination port numbers */

range_ip_src_reject(X):-(X>=158),(X=<178).                /* range of destination ip address */
range_ip_dst_reject(X):-(X>=320),(X=<360).

icmp_type_reject_list([1,312,5]).                         /*icmp type to be rejected*/





/*------------------------ALLOWED--------------Arguments----------------------------------*/
any_list([any]).              /* to allow any arguement*/
ether_vlan_id_allowlist([423,55,21]).
ether_vlan_id_allow_range(X):- (X>= 400, X=< 500).

/*adaptlist ipv4*/

adaptlist_ipv6([1,2,any]).

/**ipv6  arguments**/


isl_ipv6([1,2,3,4,5,6,7,8]).
isl2_ipv6([any]).

/*drop arguments ipv6*/

src_port_droplist_ipv6([12322,53241]).
src_port_drop_range_ipv6(X):- (X>=45),(X =<90).

dest_port_droplist_ipv6([21,4,324,432]).
dest_port_drop_range_ipv6(X) :- (X>= 22),(X=< 435).

src_ip_drop_list_ipv6([6,9,11,13]).
dst_ip_drop_list_ipv6([19,12,45,66]).

range_src_ip_drop_ipv6(X):-(X>=56),(X=<78).
range_dst_ip_drop_ipv6(X):-(X>=100),(X=<200).

ether_vlan_id_droplist_ipv6([423,55,21]).
ether_vlan_id_drop_range_ipv6(X):- (X>= 400, X=< 500).

proto_allow_list_ipv6([1,6,17]).

/*reject argumnets ipv6*/


src_port_rejectlist_ipv6([331,56,86,231]).
dest_port_rejectlist_ipv6([674,344,7867]).

src_ip_reject_list_ipv6([1,4]).
dst_ip_reject_list_ipv6([129,212]).

src_port_reject_range_ipv6(X):- (X>=21),(X=< 78).
dest_port_reject_range_ipv6(X) :- (X>= 22),(X=< 435).

range_src_ip_reject_ipv6(X):-(X>=158),(X=<178).
range_dst_ip_reject_ipv6(X):-(X>=320),(X=<360).

icmp_type_reject_list_ipv6([1,312,5]).

/*allow arguments ipv6*/



ether_vlan_id_allowlist_ipv6([423,55,21]).
ether_vlan_id_allow_range_ipv6(X):- (X>= 400, X=< 500).



/*adaptlist ipv6 arguments*/

adaptlist_ipv6([1,2,any]).













