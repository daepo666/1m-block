#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include "my_struct.h"
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <ctype.h>
#include <time.h>
/* returns packet id */
static uint32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	uint32_t mark, ifi, uid, gid;
	int ret;
	unsigned char *data, *secdata;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	if (nfq_get_uid(tb, &uid))
		printf("uid=%u ", uid);

	if (nfq_get_gid(tb, &gid))
		printf("gid=%u ", gid);

	ret = nfq_get_secctx(tb, &secdata);
	if (ret > 0)
		printf("secctx=\"%.*s\" ", ret, secdata);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d ", ret);

	fputc('\n', stdout);

	return id;
}

typedef struct host_list {
	char **hosts;
	size_t count;
	size_t cap;
} host_list;

static uint64_t now_ns(void);
static void lowercase(char *s);
static int host_cmp(const void *a, const void *b);
static int load_hosts(const char *file_name, host_list *list);
static int host_list_contains(const host_list *list, const char *host);
int bad_or_not(uint8_t *http, uint64_t http_len, const host_list *list);
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data);

static uint64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void lowercase(char *s)
{
	for (; *s; s++)
		*s = (char)tolower((unsigned char)*s);
}

static int host_cmp(const void *a, const void *b)
{
	const char *ha = *(const char * const *)a;
	const char *hb = *(const char * const *)b;
	return strcmp(ha, hb);
}

static int load_hosts(const char *file_name, host_list *list)
{
	FILE *fp = fopen(file_name, "r");
	char line[512];
	uint64_t start, end;

	if (!fp) {
		perror("fopen");
		return -1;
	}

	start = now_ns();

	while (fgets(line, sizeof(line), fp)) {
		char *host = line;
		char *comma = strchr(line, ',');
		char *p;

		if (comma)
			host = comma + 1;

		while (*host == ' ' || *host == '\t')
			host++;

		p = host + strlen(host);
		while (p > host && (p[-1] == '\n' || p[-1] == '\r' || p[-1] == ' ' || p[-1] == '\t'))
			*--p = '\0';

		if (*host == '\0')
			continue;

		lowercase(host);

		if (list->count == list->cap) {
			size_t new_cap = list->cap ? list->cap * 2 : 1024;
			char **new_hosts = realloc(list->hosts, new_cap * sizeof(char *));
			if (!new_hosts) {
				perror("realloc");
				fclose(fp);
				return -1;
			}
			list->hosts = new_hosts;
			list->cap = new_cap;
		}

		list->hosts[list->count] = strdup(host);
		if (!list->hosts[list->count]) {
			perror("strdup");
			fclose(fp);
			return -1;
		}

		list->count++;
	}

	fclose(fp);

	qsort(list->hosts, list->count, sizeof(char *), host_cmp);

	end = now_ns();

	printf("host numbers %zu\n", list->count);
	printf("load+ sort time: %.3f ms\n", (end - start) / 1000000.0);
	printf("pid ----> %d\n", getpid());

	return 0;
}

static int host_list_contains(const host_list *list, const char *host)
{
	char **found = bsearch(&host, list->hosts, list->count, sizeof(char *), host_cmp);
	return found != NULL;
}

int bad_or_not(uint8_t *http, uint64_t http_len, const host_list *list){
	const char * recvuntil = "Host:";
	if (http_len < 5){
		return 0;
	}
    
	int i,j = 0;
	for(i = 0 ; i<=http_len - 5; i++){
		if(memcmp(http +i, recvuntil, 5) !=0){
			continue;
		}

		uint8_t *candidate = http + i + 5;

		while (candidate < http + http_len && (*candidate == ' ' || *candidate == '\t')){
			candidate++;
		}
		uint64_t candidate_len = 0;

		uint64_t remain = http + http_len - candidate;

		for (j = 0; j < remain; j++) {
			if (candidate[j] == '\n' || candidate[j] == '\r') {
				break;
			}
		}
		candidate_len = j;
		
		char host[256];

	if (candidate_len == 0 || candidate_len >= sizeof(host))
		return 0;

	memcpy(host, candidate, candidate_len);
	host[candidate_len] = '\0';

	lowercase(host);

	char *colon = strchr(host, ':');
	if (colon){
		*colon = '\0';
	}
	uint64_t start = now_ns();
	int found = host_list_contains(list, host);
	uint64_t end = now_ns();

	printf("host search time: %lu ns\n", (unsigned long)(end - start));

	if (found) {
		printf("drop bad host: %s\n", host);
		return 1;
	}
	}
	return 0;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{	
	//bad host
	uint32_t id = print_pkt(nfa);
	const host_list *bad_hosts = (const host_list *)data;
	uint8_t *pkt;
	int pkt_len = nfq_get_payload(nfa, &pkt);
	if (pkt_len <= 0){
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
	ipv4_header * ip = (ipv4_header *)pkt;
	uint64_t ip_len = (ip->version_ihl &0xf)<<2;

	uint8_t version = ip->version_ihl >>4;
	if(version != 4 || ip->protocol != IPPROTO_TCP){
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}

	tcp_header * tcp = (tcp_header *)(pkt +ip_len);
	
	uint16_t some_val = ntohs(tcp->dataoffset_reversed_flags);
	uint64_t data_offset = (some_val >>12 ) &0xf;
	uint64_t tcp_len = data_offset <<2;

	//tcp is struct pointer, so + calculation may be undesired val
	uint8_t *start_http = (uint8_t *)(pkt + ip_len+ tcp_len);
	uint64_t http_len = pkt_len - ip_len - tcp_len;
	if (http_len < 6){
    	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
	if (bad_or_not(start_http, http_len, bad_hosts)) {
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}


	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	uint32_t queue = 0;
	char buf[4096] __attribute__ ((aligned));

	host_list bad_hosts = {0};

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <site list file>\n", argv[0]);
		exit(1);
	}

	if (load_hosts(argv[1], &bad_hosts) < 0){
		exit(1);
	}
	

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '%d'\n", queue);
	
	//casting to void * same as cb function's argument
	qh = nfq_create_queue(h, queue, &cb, (void *)&bad_hosts);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	printf("setting flags to request UID and GID\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve process UID/GID.\n");
	}

	printf("setting flags to request security context\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve security context.\n");
	}

	printf("Waiting for packets...\n");

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	for (size_t i = 0; i < bad_hosts.count; i++){
		free(bad_hosts.hosts[i]);
	}
	free(bad_hosts.hosts);

	exit(0);
}
