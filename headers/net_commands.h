#ifndef APOLLO_NET_COMMANDS_H
#define APOLLO_NET_COMMANDS_H

#include "types.h"
#include "network_interface.h"

void net_cmd_ping(int argc, char* args[]);
void net_cmd_nslookup(int argc, char* args[]);
void net_cmd_dhcp(int argc, char* args[]);
void net_cmd_wget(int argc, char* args[]);
void net_cmd_telnet(int argc, char* args[]);
void net_cmd_traceroute(int argc, char* args[]);
void net_cmd_tcpdump(int argc, char* args[]);
void net_cmd_route(int argc, char* args[]);
void net_cmd_arp(int argc, char* args[]);
void net_cmd_netstat(int argc, char* args[]);
void net_cmd_listen(int argc, char* args[]);

void print_dhcp_failure(network_interface_t* iface);
void print_arp_failure(network_interface_t* iface, const ip_address_t* target);
void print_qemu_network_hint(void);
void print_network_error(const char* text, uint32_t value, const char* tail);
uint32_t print_network_errors(network_interface_t* iface);
void print_network_result(network_interface_t* iface);

#endif