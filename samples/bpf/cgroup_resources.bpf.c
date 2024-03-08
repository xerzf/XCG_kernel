/* Copyright (c) 2016 Sargun Dhillon <sargun@sargun.me>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#include "vmlinux.h"
#include <string.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>




struct {
    __uint(type, BPF_MAP_TYPE_HASH); 
    __type(key, char*);             
    __type(value, char*);      
    __uint(max_entries, 4096);     
} cpu_max_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH); 
    __type(key, char*);             
    __type(value, char*);      
    __uint(max_entries, 4096);     
} cpu_sets_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH); 
    __type(key, char*);             
    __type(value, u64);      
    __uint(max_entries, 4096);     
} cpu_idle_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH); 
    __type(key, char*);             
    __type(value, u64);      
    __uint(max_entries, 4096);     
} memory_limit_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH); 
    __type(key, char*);             
    __type(value, u64);      
    __uint(max_entries, 4096);     
} memory_reser_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH); 
    __type(key, char*);             
    __type(value, u64);      
    __uint(max_entries, 4096);     
} hugetlb_2MB_limit_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH); 
    __type(key, char*);             
    __type(value, u64);      
    __uint(max_entries, 4096);     
} pids_limit_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH); 
    __type(key, char*);             
    __type(value, u64);      
    __uint(max_entries, 4096);     
} cgrp_mask_map SEC(".maps");





char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
