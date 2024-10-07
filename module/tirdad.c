/*
    By Sirus Shahini
    ~cyn
*/

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/siphash.h>
#include <linux/random.h>
#include <linux/in6.h>
#include <linux/livepatch.h>

siphash_key_t seq_secret;
siphash_key_t last_secret;

#define AGGREGATE_KEY_SIZE	16

#ifdef COLORED_OUTP
#define CNORM				"\x1b[0m"
#define CRED				"\x1b[1;31m"
#define CGREEN				"\x1b[1;32m"
#else
#define CNORM				""
#define CRED				""
#define CGREEN				""
#endif

void _s_out(u8 err, char *fmt, ...);
siphash_key_t *get_secret(void);
u32 secure_tcp_seq_hooked(__be32 , __be32 , __be16 , __be16 );
u32 secure_tcpv6_seq_hooked(const __be32 *, const __be32 *,__be16 , __be16 );
int hook_init(void);
void hook_exit(void);

void _s_out(u8 err, char *fmt, ...){
    va_list argp;
    char msg_fmt[255];


    if (err){
		strcpy(msg_fmt,CRED"[!] TIRDAD: "CNORM);
    }else{
		strcpy(msg_fmt,CGREEN"[-] TIRDAD: "CNORM);
    }
    strcat(msg_fmt,fmt);
    strcat(msg_fmt,"\n");
    va_start(argp,fmt);
    vprintk(msg_fmt,argp);
    va_end(argp);
}

siphash_key_t *get_secret(void){
	u32 temp;

	temp = *((u32*)(&seq_secret.key[0]));
	temp>>=8;
	last_secret.key[0] += temp;
	temp = *((u32*)(&seq_secret.key[1]));
	temp>>=8;
	last_secret.key[1] += temp;

	return &last_secret;
}


u32 secure_tcp_seq_hooked(__be32 saddr, __be32 daddr,
		   __be16 sport, __be16 dport)
{
	u32 hash;

	hash = siphash_3u32((__force u32)saddr, (__force u32)daddr,
			        (__force u32)sport << 16 | (__force u32)dport,
			        get_secret());
	return hash;
}


u32 secure_tcpv6_seq_hooked(const __be32 *saddr, const __be32 *daddr,
		     __be16 sport, __be16 dport)
{
	const struct {
		struct in6_addr saddr;
		struct in6_addr daddr;
		__be16 sport;
		__be16 dport;
	} __aligned(SIPHASH_ALIGNMENT) combined = {
		.saddr = *(struct in6_addr *)saddr,
		.daddr = *(struct in6_addr *)daddr,
		.sport = sport,
		.dport = dport
	};
	u32 hash;

	hash = siphash(&combined, offsetofend(typeof(combined), dport),
		       get_secret());
	return hash;
}

static struct klp_func funcs[] = {
 	{
 		.old_name = "secure_tcp_seq",
		.new_func = secure_tcp_seq_hooked,
	},
	{
		.old_name = "secure_tcpv6_seq",
		.new_func = secure_tcpv6_seq_hooked,
	}, { }
};

static struct klp_object objs[] = {
	{
	.funcs = funcs,
	}, { }
};

static struct klp_patch patch = {
	.mod = THIS_MODULE,
	.objs = objs,
};

int hook_init(void){
	int i;

#if !IS_ENABLED(CONFIG_IPV6)

	/*
	 *	A fail-safe for an extremely unlikely situation.
	 *	If you have a strange custom kernel without IPv6 support,
	 *	revert to the older versions of tirdad (like commit: 1742ca6).
	*/

	_s_out(1,"IPv6 is not supported in your system.");
	return -1;
#endif

	memset(&seq_secret.key,0,AGGREGATE_KEY_SIZE);

	/*
	 *	read some random bytes
	*/

	if (wait_for_random_bytes()){
		_s_out(1,"FATAL: Can't get random bytes form kernel.");
		return -1;
	}

	get_random_bytes(&seq_secret.key,AGGREGATE_KEY_SIZE);

	for (i=0;i<32;i++){
		if ( *( ((u8*)(&seq_secret.key)) + i ) !=0)
			break;
	}

	if (i==32){
		_s_out(1,"FATAL: Random bytes are not valid.");
		return -1;
	}

	memcpy(&last_secret,&seq_secret,AGGREGATE_KEY_SIZE);

	/*
	 *	Ok, initialization must have succeeded.
	 *	Install the hook
	*/

	_s_out(0,"Installing hooks via Livepatch.");

	return klp_enable_patch(&patch);
}

void hook_exit(void){
}
module_init(hook_init);
module_exit(hook_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sirus Shahini <sirus.shahini@gmail.com>");
MODULE_DESCRIPTION("Tirdad hook for TCP ISN generator");
MODULE_INFO(livepatch, "Y");
