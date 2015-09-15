/*
 *	itrace.c: attches to an already existing process and 
 *		  prints the x86 intructions currently being executed
 *
 *   Name: Brandon Brien
 *   ID: 10079883
 *   CPSC 457 Assignment 1, Part 1
 *   Due: Oct 17, 2014
 *   Last Edited: Oct 16, 2014
 *
 *
 *  *It should be noted that this program was based off Dr. Locasto's
 *   example of ptrace. Some functions are very similar. Those sections 
 *   are heavily commented to show understanding of whats happening.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <asm/ptrace-abi.h>
#include <asm/ptrace.h>
#include <udis86.h>

/* The process ID to trace. */
long int tr_pid = 0;

static void do_trace();
static void init_attach(char*);
void sigintHandler(int);


/* 
 * Handles the the event that a SIGINT is send kill
 * the process. Destroys itself and the tracee process
 */
void sigintHandler(int sig_num)
{
	int killed_status;
	ptrace(PTRACE_KILL, tr_pid, NULL, NULL);
	printf("\nitrace and traced program killed\n");
	waitpid(tr_pid,&killed_status, WUNTRACED | WCONTINUED);
	exit(0);
}

/* 
 * Attempts to attach to tracee
 */
static void
init_attach(char* tpid)
{
  int stopped = 0; /* used to determine if the process as been stopped via attach */
  long atch_success = 0;  /*used to determine if there was an error attaching */
  pid_t p = 0;
  int attach_status = 0;
 
  /*
   * Because the arg value is a string, must cast to long
   */
  tr_pid = strtol(tpid, NULL, 10);

  printf("itrace is now attempting to trace the process: %ld\n",tr_pid);

  atch_success = ptrace(PTRACE_ATTACH,tr_pid,NULL,NULL);

  if(atch_success==-1)
  {
    fprintf(stderr,"itrace has failed to attach to the process\n");
    exit(-1);
  }


  /*
   * waits until the traced process has ACTUALLY stopped
   * because sometimes the signal takes longer than expected
   */
  p = waitpid(tr_pid, &attach_status, WUNTRACED | WCONTINUED);

  /*
   * Prints the appropirate message to stdout depdning on results
   */
  if(WIFSTOPPED(attach_status))
  {
    stopped = WSTOPSIG(attach_status);
    printf("Attaching to the tracee has been succesful");
  }else{
    printf("The attempt to attach to process has failed");
    exit(-2);
  }

  return;
}


/*
 * Function do_trace assumes that itrace as been attached (successfully)
 * to a process. It then output to stdout all the x86 instructions being
 * executed by traced program
 */
static void 
do_trace()
{
	struct user_regs_struct registers; /* A struct to hold all registers of process */
	size_t read_size = 15; /* how many bytes the disassembler should read */
	unsigned char *buff; 
	long eip_data[4]; /* a holding place for all the 15 bytes of eip (max intruction size) */
	buff = (unsigned char *) malloc(sizeof(unsigned char)*15); 
	int stop_status = 0;

 	/* Loops until no more instructinos are being read */
	do
	{
		ptrace(PTRACE_GETREGS, tr_pid, NULL, &registers);
	
		eip_data[0]= ptrace(PTRACE_PEEKDATA, tr_pid, registers.eip, NULL);
		eip_data[1]= ptrace(PTRACE_PEEKDATA, tr_pid, registers.eip+4, NULL);
		eip_data[2]= ptrace(PTRACE_PEEKDATA, tr_pid, registers.eip+8, NULL);
		eip_data[3]= ptrace(PTRACE_PEEKDATA, tr_pid, registers.eip+12, NULL);
	
		memcpy(buff, eip_data, 15);
		
		/* Initialization of 3rd part disassembler */
		ud_t ud_obj;
		ud_init(&ud_obj);
	    	ud_set_mode(&ud_obj, 32);
		ud_set_syntax(&ud_obj, UD_SYN_INTEL);
		ud_set_input_buffer(&ud_obj, buff, read_size);
	
		ud_disassemble(&ud_obj);
		
		/* Prints the disassembled x86 code */
		printf("\t%s\n", ud_insn_asm(&ud_obj));

 		/* Tells the tracee to go to the next instruction, then wait */		
		ptrace(PTRACE_SINGLESTEP,tr_pid, 0,NULL);

		/* Waits until the tracee program as gon to the next intSruction
		   and STOPPED before itrace continues */
		waitpid(tr_pid, &stop_status, WUNTRACED|WCONTINUED);
		if(!stop_status)
		{
			printf("Something has gone wrong");
		
		}

	}while (eip_data[0] != -1);

  return;
}


/* Main function for itrace that
 * sets up the attached to process ID
 * given on commmand line and then 
 * calls do_trace to do the tracing
 */
int main(int argc,
	 char* argv[])
{
  if(3==argc)
  {
    init_attach(argv[2]);
    signal(SIGINT, sigintHandler);
    do_trace();
  }
  return 0;
}
