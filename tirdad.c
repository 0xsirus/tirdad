/*
    By Sirus Shahini
    ~cyn
*/

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kernel.h>
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
#include <linux/cryptohash.h>
#include <linux/siphash.h>

int _clog = 1;

char *_seq_secret;
char *_tcp_secure_seq_adr;

module_param(_seq_secret,charp,0);
module_param(_tcp_secure_seq_adr,charp,0);

siphash_key_t seq_secret;
siphash_key_t last_secret;

unsigned long tcp_secure_seq_adr;
u8 p_bits;
u8 backup_bytes[12];

u32 secure_tcp_seq_hooked(__be32 saddr, __be32 daddr,
		   __be16 sport, __be16 dport)
{
	u32 hash;
	u32 temp;

	temp = *((u32*)(&seq_secret.key[0]));
	temp>>=8;
	last_secret.key[0] += temp;
	temp = *((u32*)(&seq_secret.key[1]));
	temp>>=8;
	last_secret.key[1] += temp;
	
	hash = siphash_3u32((__force u32)saddr, (__force u32)daddr,
			        (__force u32)sport << 16 | (__force u32)dport,
			        &last_secret);	
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
	if (!!( ps & *((unsigned long*)pud) ) == 1){
	    return 1;
	}
	pmd = pmd_offset(pud, address);
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
	if (!!( ps & *((unsigned long*)pmd) ) == 1){
	    return 1;
	}	
    ptep=pte_offset_map(pmd, address);	
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


int hook_init(void){	
	char keys[2][17];
    int i;   
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
    
	
    keys[0][16]=keys[1][16]=0;
    	
	for (i=0;i<32;i++){
		keys[i/16][i%16] = _seq_secret[i]; 
	}

 	sscanf(keys[0],"%016lx",(unsigned long*)&seq_secret.key[0]);
 	sscanf(keys[1],"%016lx",(unsigned long*)&seq_secret.key[1]);

    memcpy(&last_secret,&seq_secret,sizeof(seq_secret));
    
    sscanf(_tcp_secure_seq_adr,"%016lx",&tcp_secure_seq_adr);

    
	p_bits=0;
       
	mm = current->mm; 
	pgd = pgd_offset(mm, tcp_secure_seq_adr); 
		
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
		return -1; //EPERM but we use as generic error number
	
	ent_val = *((unsigned long*)pgd); 			
	cbit = ent_val & 2;
	if (cbit) p_bits = 1;	
	p4d = p4d_offset(pgd,tcp_secure_seq_adr);
		
	pud = pud_offset(p4d, tcp_secure_seq_adr); 	
	ent_val = *((unsigned long*)pud);
	cbit = ent_val & 2;
	if (cbit) p_bits = p_bits | 2;
	
	if (!!( ps & *((unsigned long*)pud) ) == 1){    
	    goto install;
	}

	pmd = pmd_offset(pud, tcp_secure_seq_adr);
	VM_BUG_ON(pmd_trans_huge(*pmd));
	ent_val = *((unsigned long*)pmd);
	cbit = ent_val & 2;
	if (cbit) p_bits = p_bits | 4;
	
	if (!!( ps & *((unsigned long*)pmd) ) == 1){
	    goto install;
	}

    ptep=pte_offset_map(pmd, tcp_secure_seq_adr);
	
	if (!ptep){
		return -1;
	
	}
	ent_val = *((unsigned long*)(ptep));  
	cbit = ent_val & 2;
	if (cbit) p_bits = p_bits | 8;

    
    
install:    
    
    store_p_bits(tcp_secure_seq_adr,0x0F);
      
    payload_adr = (u8*) tcp_secure_seq_adr;
    memcpy(backup_bytes,(void*)tcp_secure_seq_adr,12);
    memcpy((void*)tcp_secure_seq_adr,payload,12);   
    *((unsigned long*)&payload_adr[2]) = (unsigned long)&secure_tcp_seq_hooked;

    store_p_bits(tcp_secure_seq_adr,p_bits);       
    
    printk("[>] Installing tirdad hook succeeded.\n");
    
	return 0;
}

void hook_exit(void){  
    store_p_bits(tcp_secure_seq_adr,0x0F);    
    memcpy((void*)tcp_secure_seq_adr,backup_bytes,12);       
    store_p_bits(tcp_secure_seq_adr,p_bits);  
    
    printk("[>] Removed tirdad hook successfully\n");
}
module_init(hook_init);
module_exit(hook_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sirus Shahini <sirus.shahini@gmail.com>");
MODULE_DESCRIPTION("Tirdad hook for TCP ISN generator");
