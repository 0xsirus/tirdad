/*
    By Sirus Shahini
    ~cyn

    Streamline patching as suggested by ArrayBolt3.
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
u32 secure_tcp_seq_hooked(__be32 , __be32 , __be16 , __be16 );
u32 secure_tcpv6_seq_hooked(const __be32 *, const __be32 *,__be16 , __be16 );
int hook_init(void);
void hook_exit(void);


void _s_out(u8 err, char *fmt, ...){
	va_list argp;
	char msg_fmt[255];

	if (err){
		snprintf(msg_fmt, 255, CRED"[!] TIRDAD: "CNORM"%s\n", fmt);
	}else{
		snprintf(msg_fmt, 255, CGREEN"[-] TIRDAD: "CNORM"%s\n", fmt);
	}

	va_start(argp,fmt);
	vprintk(msg_fmt,argp);
	va_end(argp);
}

u32 secure_tcp_seq_hooked(__be32 saddr, __be32 daddr,
		   __be16 sport, __be16 dport)
{
	u32 hash;
	get_random_bytes(((char *)&hash), sizeof(u32));
	return hash;
}


u32 secure_tcpv6_seq_hooked(const __be32 *saddr, const __be32 *daddr,
		     __be16 sport, __be16 dport)
{
	u32 hash;
	get_random_bytes(((char *)&hash), sizeof(u32));
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
#if !IS_ENABLED(CONFIG_IPV6)

	/*
	 *	A fail-safe for an extremely unlikely situation.
	 *	If you have a strange custom kernel without IPv6 support,
	 *	revert to the older versions of tirdad (like commit: 1742ca6).
	*/

	_s_out(1,"IPv6 is not supported in your system.");
	return -1;
#endif

	/*
	 *	ensure RNG is initialized
	 */

	if (wait_for_random_bytes()){
		_s_out(1,"FATAL: Can't get random bytes from kernel.");
		return -1;
	}

	/*
	 *	Ok, initialization must have succeeded.
	 *	Install the hook
	 */

	_s_out(0,"Installing hooks via Livepatch.");

	return klp_enable_patch(&patch);
}

void hook_exit(void){
	_s_out(0,"Removed hooks. Exiting normally.");
}

module_init(hook_init);
module_exit(hook_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sirus Shahini <sirus.shahini@gmail.com>");
MODULE_DESCRIPTION("Tirdad hook for TCP ISN generator");
MODULE_INFO(livepatch, "Y");

