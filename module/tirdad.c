/*
    By Sirus Shahini
    ~cyn
*/

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/mm_types.h>
#include <linux/page-flags.h>
#include <linux/mmzone.h>
#include <linux/gfp.h>
#include <linux/pfn.h>
#include <linux/hugetlb.h>
#include <linux/syscalls.h>
#include <asm/cacheflush.h>
#include <asm/uaccess.h>
#include <linux/utsname.h>
#include <linux/moduleparam.h>
#include <linux/siphash.h>
#include <linux/random.h>
#include <linux/kprobes.h>
#include <linux/in6.h>

siphash_key_t seq_secret;
siphash_key_t last_secret;


#define AGGREGATE_KEY_SIZE	16
#define FUSION_SIZE		12


struct target_vals{
	unsigned long adr;
	unsigned long hook_adr;
	u8 backup_bytes[FUSION_SIZE];

	/*
	 *	We expect the two target functions to be
	 *	placed on the same page but we treat them
	 *	independently anyways.
	*/
	u8 p_bits;
} seqv4,seqv6;


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
int store_p_bits(unsigned long , unsigned char );
int install_hook_on(struct target_vals *);
void recover_one(struct target_vals *);
int get_kasln_adr(void);
int hook_init(void);
void hook_exit(void);
int preh_hk(struct kprobe * kp, struct pt_regs *);
void posth_hk(struct kprobe * kp, struct pt_regs *,unsigned long);


#ifdef pte_offset_map
#define _pte_direct pte_offset_map
#else
#define _pte_direct __pte_map
#endif


u64 kasln_adr=0;

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

int store_p_bits(unsigned long address, unsigned char bits){
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;
	p4d_t *p4d;
	unsigned long ent_val;
	struct mm_struct *mm;

	unsigned short ps = 1 << 7;
	u8 cbit;
	u8 op_num;

	mm = current->mm;
	pgd = pgd_offset(mm, address);

	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd))){
		return -1;
	}
	ent_val = *((unsigned long*)pgd);
	op_num = 1;
	cbit = bits & op_num;
	if (cbit){
	    ent_val = ent_val | 2;
	}else{
	    ent_val = ent_val & ~((u8)2);
	}
	*((unsigned long*)pgd) = ent_val;

	p4d = p4d_offset(pgd,address);
	pud = pud_offset(p4d, address);

	ent_val = *((unsigned long*)pud);
	op_num = 2;
	cbit = bits & op_num;
	if (cbit){
	    ent_val = ent_val | 2;
	}else{
	    ent_val = ent_val & ~((u8)2);
	}
	*((unsigned long*)pud) = ent_val;
	if (!!( ps & ent_val ) == 1){
	    return 1;
	}
	pmd = pmd_offset(pud, address);
	/*
	 *	We don't have to check for this
	 *	but if this macro triggers a bug
	 *	here there's already something wrong
	 *	with mappings.
	 *	I leave it to stay here for the
	 *	sake of completeness.
	*/
	VM_BUG_ON(pmd_trans_huge(*pmd));
	ent_val = *((unsigned long*)pmd);

	op_num = 4;
	cbit = bits & op_num;
	if (cbit){
	    ent_val = ent_val | 2;
	}else{
	    ent_val = ent_val & ~((u8)2);
	}
	*((unsigned long*)pmd) = ent_val;
	if (!!( ps & ent_val ) == 1){
	    return 1;
	}
	ptep=_pte_direct(pmd, address);
	if (!ptep){
		return -1;
	}
	ent_val = *((unsigned long*)(ptep));
	op_num = 8;
	cbit = bits & op_num;
	if (cbit){
	    ent_val = ent_val | 2;
	}else{
	    ent_val = ent_val & ~((u8)2);
	}
	*((unsigned long*)ptep) = ent_val;
	return 1;
}

int install_hook_on(struct target_vals *target){
	char payload[] = "\x48\xB8\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xE0";
	u8* payload_adr;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;
	unsigned long ent_val;
	struct mm_struct *mm;
	unsigned short ps = 1 << 7;
	u8 cbit;
	u8 p_bits;

	p_bits=0;

	mm = current->mm;
	pgd = pgd_offset(mm, target->adr);

	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd))){
		_s_out(1,"FATAL: Page tables not accessible.");
		return -1;
	}

	ent_val = *((unsigned long*)pgd);
	cbit = ent_val & 2;
	if (cbit) p_bits = 1;
	p4d = p4d_offset(pgd,target->adr);

	pud = pud_offset(p4d, target->adr);
	ent_val = *((unsigned long*)pud);
	cbit = ent_val & 2;
	if (cbit) p_bits = p_bits | 2;

	if (!!( ps & ent_val ) == 1){
	    goto install;
	}

	pmd = pmd_offset(pud, target->adr);
	VM_BUG_ON(pmd_trans_huge(*pmd));
	ent_val = *((unsigned long*)pmd);
	cbit = ent_val & 2;
	if (cbit) p_bits = p_bits | 4;

	if (!!( ps & ent_val ) == 1){
	    goto install;
	}

	ptep=_pte_direct(pmd, target->adr);

	if (!ptep){
		_s_out(1,"FATAL: Page table entry not accessible.");
		return -1;
	}

	ent_val = *((unsigned long*)(ptep));
	cbit = ent_val & 2;
	if (cbit) p_bits = p_bits | 8;

install:

	store_p_bits(target->adr,0x0F);

	payload_adr = (u8*) target->adr;
	memcpy(target->backup_bytes,(void*)target->adr,FUSION_SIZE);
	memcpy((void*)target->adr,payload,FUSION_SIZE);
	*((unsigned long*)&payload_adr[2]) = target->hook_adr;

	/*
	 * Revert entries to original values.
	*/
	store_p_bits(target->adr,p_bits);

	target->p_bits=p_bits;

	return 0;
}

void recover_one(struct target_vals *target){
	store_p_bits(target->adr,0x0F);
	memcpy((void*)target->adr,target->backup_bytes,FUSION_SIZE);
	store_p_bits(target->adr,target->p_bits);
}

#define SYMBOL_LOOKUP(s) (((u64 (*)(const char *))(kasln_adr))(s))
#define HANDLER(t,l,ret,...) t l ## h_hk(struct kprobe * kp, struct pt_regs * r\
					__VA_OPT__(,) __VA_ARGS__){\
						ret;\
					}

HANDLER(int,pre,return 0)
HANDLER(void,post,return,unsigned long flags)

int get_kasln_adr(void){
	struct kprobe h_kprobe;
	int r;

	memset(&h_kprobe, 0, sizeof(h_kprobe));
	h_kprobe.pre_handler = preh_hk;
	h_kprobe.post_handler = posth_hk;
	h_kprobe.symbol_name = "kallsyms_lookup_name";
	r = register_kprobe(&h_kprobe);
	if (!r){
		kasln_adr=(u64)h_kprobe.addr;
	}
	unregister_kprobe(&h_kprobe);

	return r;
}


int hook_init(void){
	int i;

	if (get_kasln_adr()){
		_s_out(1,"FATAL: Can't find kallsyms_lookup_name.");
		return -1;
	}

#if !IS_ENABLED(CONFIG_IPV6)

	/*
	 *	A fail-safe for an extremely unlikely situation.
	 *	If you have a strange custom kernel without IPv6 support,
	 *	revert to the older versions of tirdad (like commit: 1742ca6).
	*/

	_s_out(1,"IPv6 is not supported in your system.");
	return -1;
#endif

	seqv4.adr = 0;
	seqv6.adr = 0;

	memset(&seq_secret.key,0,AGGREGATE_KEY_SIZE);

	/*
	 *	Find our function of interest and
	 *	read some random bytes
	 *	We don't directly call kallsyms_lookup_name()
	 *	as it's not exported in newer kernels.
	*/

	seqv4.adr = SYMBOL_LOOKUP("secure_tcp_seq");
	seqv4.hook_adr=(u64)&secure_tcp_seq_hooked;

	seqv6.adr = SYMBOL_LOOKUP("secure_tcpv6_seq");
	seqv6.hook_adr=(u64)&secure_tcpv6_seq_hooked;

	if (!seqv4.adr || !seqv6.adr){
		_s_out(1,"FATAL: Name lookup failed.");
		return -1; //EPERM but we use it as a generic error number
	}

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
	 *	Prepare the page tables and install the hook
	*/

	if (install_hook_on(&seqv4) ||
		install_hook_on(&seqv6))
	{
		_s_out(1,"FATAL: Operation failed.");
		return -1;
	}

	_s_out(0,"Hooks are ready. Operation completed without errors.");

	return 0;
}

void hook_exit(void){
	recover_one(&seqv4);
	recover_one(&seqv6);

	_s_out(0,"Removed hooks. Exiting normally.");
}
module_init(hook_init);
module_exit(hook_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sirus Shahini <sirus.shahini@gmail.com>");
MODULE_DESCRIPTION("Tirdad hook for TCP ISN generator");
