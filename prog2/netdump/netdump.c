#define RETSIGTYPE void
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef setsignal_h
#define setsignal_h

RETSIGTYPE (*setsignal(int, RETSIGTYPE (*)(int)))(int);
#endif

char cpre580f98[] = "netdump";

/* Prog2 counters */
uint nether, nipv4, ntcp, nudp, nbroadcast;

void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p);

int packettype;

char *program_name;

/* Externs */
extern void bpf_dump(const struct bpf_program *, int);

extern char *copy_argv(char **);

/* Forwards */
void program_ending(int);

/* Length of saved portion of packet. */
int snaplen = 1500;
;

static pcap_t *pd;

extern int optind;
extern int opterr;
extern char *optarg;
int pflag = 0, aflag = 0;

int
main(int argc, char **argv)
{
	int cnt, op, i, done = 0;
	bpf_u_int32 localnet, netmask;
	char *cp, *cmdbuf, *device;
	struct bpf_program fcode;
	void (*oldhandler)(int);
	u_char *pcap_userdata;
	char ebuf[PCAP_ERRBUF_SIZE];

	cnt = -1;
	device = NULL;

	if ((cp = strrchr(argv[0], '/')) != NULL)
		program_name = cp + 1;
	else
		program_name = argv[0];

	opterr = 0;
	while ((i = getopt(argc, argv, "pa")) != -1)
	{
		switch (i)
		{
		case 'p':
			pflag = 1;
			break;
		case 'a':
			aflag = 1;
			break;
		case '?':
		default:
			done = 1;
			break;
		}
		if (done) break;
	}
	if (argc > (optind)) cmdbuf = copy_argv(&argv[optind]);
	else cmdbuf = "";

	if (device == NULL) {
		device = pcap_lookupdev(ebuf);
		if (device == NULL)
			error("%s", ebuf);
	}
	pd = pcap_open_live(device, snaplen,  1, 1000, ebuf);
	if (pd == NULL)
		error("%s", ebuf);
	i = pcap_snapshot(pd);
	if (snaplen < i) {
		warning("snaplen raised from %d to %d", snaplen, i);
		snaplen = i;
	}
	if (pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0) {
		localnet = 0;
		netmask = 0;
		warning("%s", ebuf);
	}
	/*
	 * Let user own process after socket has been opened.
	 */
	setuid(getuid());

	if (pcap_compile(pd, &fcode, cmdbuf, 1, netmask) < 0)
		error("%s", pcap_geterr(pd));

	(void)setsignal(SIGTERM, program_ending);
	(void)setsignal(SIGINT, program_ending);
	/* Cooperate with nohup(1) */
	if ((oldhandler = setsignal(SIGHUP, program_ending)) != SIG_DFL)
		(void)setsignal(SIGHUP, oldhandler);

	if (pcap_setfilter(pd, &fcode) < 0)
		error("%s", pcap_geterr(pd));
	pcap_userdata = 0;
	(void)fprintf(stderr, "%s: listening on %s\n", program_name, device);
	if (pcap_loop(pd, cnt, raw_print, pcap_userdata) < 0) {
		(void)fprintf(stderr, "%s: pcap_loop: %s\n",
		    program_name, pcap_geterr(pd));
		exit(1);
	}
	pcap_close(pd);
	exit(0);
}

/* routine is executed on exit

	TODO
*/
void program_ending(int signo)
{
	struct pcap_stat stat;

	if (pd != NULL && pcap_file(pd) == NULL) {
		fflush(stdout);
		putc('\n', stderr);

		if (pcap_stats(pd, &stat) < 0)
			fprintf(stderr, "pcap_stats: %s\n", pcap_geterr(pd));
		else {
			fprintf(stderr, "%d packets received by filter\n", stat.ps_recv);
			fprintf(stderr, "%d packets dropped by kernel\n", stat.ps_drop);
		}
	}

	fprintf(stderr, "%d Ether packets\n", nether);
	fprintf(stderr, "%d IPv4 packets\n", nipv4);
	fprintf(stderr, "%d TCP packets\n", ntcp);
	fprintf(stderr, "%d UDP packets\n", nudp);
	fprintf(stderr, "%d broadcast packets\n", nbroadcast);

	// TODO -- program 3 stats

	exit(0);
}

/* Like default_print() but data need not be aligned */
void
default_print_unaligned(register const u_char *cp, register u_int length)
{
	register u_int i, s;
	register int nshorts;

	nshorts = (u_int) length / sizeof(u_short);
	i = 0;
	while (--nshorts >= 0) {
		if ((i++ % 8) == 0)
			(void)printf("\n\t\t\t");
		s = *cp++;
		(void)printf(" %02x%02x", s, *cp++);
	}
	if (length & 1) {
		if ((i % 8) == 0)
			(void)printf("\n\t\t\t");
		(void)printf(" %02x", *cp);
	}
}

/*
 * By default, print the packet out in hex.
 */
void
default_print(register const u_char *bp, register u_int length)
{
	register const u_short *sp;
	register u_int i;
	register int nshorts;

	if ((long)bp & 1) {
		default_print_unaligned(bp, length);
		return;
	}
	sp = (u_short *)bp;
	nshorts = (u_int) length / sizeof(u_short);
	i = 0;
	while (--nshorts >= 0) {
		if ((i++ % 8) == 0)
			(void)printf("\n\t");
		(void)printf(" %04x", ntohs(*sp++));
	}
	if (length & 1) {
		if ((i % 8) == 0)
			(void)printf("\n\t");
		(void)printf(" %02x", *(u_char *)sp);
	}
}

/*
	TODO
	
	#5
	== Ethernet			X
	- dest 				X
	- source			X
	- type (hex)		X
	- length (decimal)	X
	
	== IP
	- payload = IP		X
	- payload = ARP		X

	== Counters 
	- broadcast packets (if dest == FF:FF:FF:FF:FF:FF)	X
	
	#6
	
	== ARP
	- request or reply (if identifiable)
	- print IP addresses (std format)
	- print all other data
	
	== IP
	- print IP addresses (std format)
	- print all other data
	
	== ICMP
	- print IP addresses (std format)
	- print all other data

	== Counters 
	- ICMP packets
	
	#7
	
	== TCP
	- print TCP header info
	- print options (if any) in hex
	- print all other data
	
	== Counters
	- TCP packets				X
	- DNS packets
*/
void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
	u_int length = h->len;
	u_int caplen = h->caplen;

	default_print(p, caplen);
	putchar('\n');
	
	/* == Begin Program 2 additions == */
	putchar('\n');

	uint16_t	ethertype;
	char		destmac[18];
	char		srcmac[18];
	
	// === Ethernet Frame
	nether++;

	// Destination MAC
	snprintf(destmac, 18, "%02X:%02X:%02X:%02X:%02X:%02X", p[0], p[1], p[2], p[3], p[4], p[5]);
	printf("DEST Address = %s\n", destmac);
	
	if(strcmp(destmac, "FF:FF:FF:FF:FF:FF") == 0)
		nbroadcast++;
	
	// Source MAC
	snprintf(srcmac, 18, "%02X:%02X:%02X:%02X:%02X:%02X", p[6], p[7], p[8], p[9], p[10], p[11]);
	printf("SRC Address = %s\n", srcmac);

	// Ethernet type
	ethertype = p[12] * 256 + p[13];

	// Check if ethertype is < 1536, if so, it's a payload size
	if(ethertype < 1536)
		goto PAYLEN;

	printf("Type = %04X ", ethertype);

	switch(ethertype) {
	case 0x800:
		printf("→ IPv4\n");
		nipv4++;
		printf("Payload = IPv4\n");
	case 0x806:
		printf("→ ARP\n");
		printf("Payload = ARP\n");
	case 0x86DD:
		printf("→ IPv6\n");
		printf("Payload = IPv6\n");
	default:
		printf("→ [UNDEFINED]\n");
	}

	goto IP;
	
	// Payload length
	PAYLEN:
	
	printf("LEN = %d\n", ethertype);
	
	// === IP Header
	IP:
	
	
	// Ending
	printf("\n----------\n");
}

