// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2016 Sargun Dhillon <sargun@sargun.me>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "cgroup_helpers.h"
#include <sys/stat.h>
#include <unistd.h>


#define CGROUP_PATH		"/sys/fs/cgroup/bb-test"

int main(int argc, char **argv)
{
	__u64 local_pid = getpid();
	int idx = 0, rc = 1;
	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;
	char filename[256];
	int map_fd[3];
	struct bpf_map *map1;


	snprintf(filename, sizeof(filename), "%s.bpf.o", argv[0]);
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 0;
	}

	char *user_file = "/sys/fs/bpf/User_pid_map";
	int user_map_fd = bpf_obj_get(user_file);

	if (user_map_fd < 0) {
		printf("Failed to user maps from BPFS, so create one\n");
		user_map_fd =  bpf_map_create(BPF_MAP_TYPE_HASH, NULL,
					sizeof(char*), sizeof(pid_t),
					1, NULL);
		if (user_map_fd < 0) {
			printf("usermap create error n");
			return 0;
		}

		rc = bpf_obj_pin(user_map_fd,user_file);
		if (rc < 0) {
			printf("bpf_obj_pin error \n");
			return 0;
		}
	}

	map1 =  bpf_object__find_map_by_name(obj, "User_pid_map");
	if (!map1) {
		fprintf(stderr, "ERROR: finding the User_pid_map in obj file failed\n");
		goto cleanup;
	}

	rc = bpf_map__reuse_fd(map1 ,user_map_fd);

	local_pid = 26912;
	char cgrpname[] = "bb-test\0"; 
	if (bpf_map_update_elem(user_map_fd, cgrpname, &local_pid, BPF_ANY)) {
		log_err("Adding target cgroup to map");
		goto err;
	}


	int result = mkdir(CGROUP_PATH, 0731);

	if (result == 0) {
        printf("目录创建成功\n");
    } else {
        printf("目录创建失败\n");
		goto err;
    }

	// if (setup_cgroup_environment())
	// 	goto err;

	// cg2 = create_and_get_cgroup(CGROUP_PATH);

	// if (cg2 < 0)
	// 	goto err;

	// if (join_cgroup(CGROUP_PATH))
	// 	goto err;

	/*
	 * The installed helper program catched the sync call, and should
	 * write it to the map.
	 */


	// sync();
	// bpf_map_lookup_elem(map_fd[2], &idx, &remote_pid);

	// result = rmdir(CGROUP_PATH);

	// if (local_pid != remote_pid) {
	// 	fprintf(stderr,
	// 		"BPF Helper didn't write correct PID to map, but: %d\n",
	// 		remote_pid);
	// 	goto err;
	// } else {
	// 	fprintf(stdout,
	// 		"BPF Helper write correct PID to map: %d\n",
	// 		remote_pid);
	// }

	rc = 0;
	
err:
 	
	// if (cg2 != -1)
	// 	close(cg2);

	// cleanup_cgroup_environment();

cleanup:
	return rc;
}
