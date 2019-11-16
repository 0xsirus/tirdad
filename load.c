/*
	By Sirus Shahini
	~cyn
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define u8					uint8_t
#define u16					uint16_t
#define u32					uint32_t
#define u64					uint64_t
#define SEC_LEN				16

char kallsyms[] = "/proc/kallsyms";
unsigned long secure_tcp_seq_adr;

unsigned long get_adr(char *symbol_name,char *file){
	char cmd[255];    
	int a;    
	char buf[5000];
	int index=0;
	unsigned long adr;
    
	sprintf(cmd,"grep %s %s | awk -F' ' '{print $1}'",symbol_name,file);
	FILE *f = popen(cmd,"r");
	while ((a=fgetc(f))!=EOF){
		buf[index++] = a;
	}
	pclose(f);
	sscanf(buf,"%016lx",&adr);
	if (adr==0){
		printf("[!] Couldn't resolve address for %s from %s\n",symbol_name,file);
		exit(-1);
	}
	printf("[>] Resolved adr 0x%016lx for %s in %s\n",adr,symbol_name,file);
	return adr;     
}
void print_usage(){
	printf("Usage: load start/stop\n");
	exit(-1);
}
int main(int argc,char **argv){
    unsigned long delta=0;
    char cmd[255];
    u8 sec_rnd[SEC_LEN];
    char sec_str[SEC_LEN*2+1];    
    int f_rand;
    int i;
    char cwd[512];
    	
    if (argc!=2)
    	print_usage();
    	
    if (!strcmp(argv[1],"start")){
		getcwd(cwd,511);
		sec_str[0] = 0;
		f_rand=open("/dev/urandom",O_RDONLY);
		if (f_rand<1){
			perror("open");
			exit(-1);
		}
		
		for (i=0;i<SEC_LEN;i++){
			char tmp[3];
			int n;
			
			n=read(f_rand,&sec_rnd[i],1);
			if (n==0){
				perror("not enough random bytes");
				exit(-1);
			}
			sprintf(tmp,"%02hhx",sec_rnd[i]);
			strcat(sec_str,tmp);
		} 
		
		secure_tcp_seq_adr = get_adr("secure_tcp_seq",kallsyms);
		sprintf(cmd,"insmod %s/tirdad.ko _seq_secret='%s' _tcp_secure_seq_adr='%016lx'",cwd,sec_str,secure_tcp_seq_adr);		
		printf("[>] Installing module...\n"); 
		system(cmd);
		printf("[>] Exiting normally...\n");
 	}else if(!strcmp(argv[1],"stop")){
 		printf("[>] Disabling module...\n"); 
		system("rmmod tirdad");
		printf("[>] Exiting normally...\n");	
 	}else{
		print_usage();
	}
    return 0;
}
