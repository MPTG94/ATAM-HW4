/* Code sample: using ptrace for simple tracing of a child process.
**
** Note: this was originally developed for a 32-bit x86 Linux system; some
** changes may be required to port to x86-64.
**
** Eli Bendersky (http://eli.thegreenplace.net)
** This code is in the public domain.
*/
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#define ARG_BUF 256

pid_t run_target(const char *programname, const char *args) {
    pid_t pid;

    pid = fork();

    if (pid > 0) {
        return pid;

    } else if (pid == 0) {
        /* Allow tracing of this process */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(1);
        }
        /* Replace this process's image with the given program */
        printf("Running the program %s with args %s\n", programname, args);
        execl(programname, args, NULL);

    } else {
        // fork error
        perror("fork");
        exit(1);
    }
}

void run_breakpoint_debugger(pid_t child_pid, unsigned long addr, int copyOrRedi, char *outFile) {
    int wait_status;
    struct user_regs_struct regs;
    struct user_regs_struct old_regs;
    int outputFile = open(outFile, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    /* Wait for child to stop on its first instruction */
    wait(&wait_status);
    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    while (regs.rip != addr) {
        ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
        // Wait for child to stop on it's next instruction
        wait(&wait_status);
        // Get regs again so we have updated rip
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    }
    // We reached the address we want to start redirecting output from
    unsigned long rspAtCallStart = regs.rsp;
    unsigned long retAddressAfterSyscalls = ptrace(PTRACE_PEEKDATA, child_pid, (void*) rspAtCallStart, NULL);

    unsigned long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) retAddressAfterSyscalls, NULL);
    printf("DBG: Original data at 0x%x: 0x%x\n", retAddressAfterSyscalls, data);

    /* Write the trap instruction 'int 3' into the address */
    unsigned long data_trap = (data & 0xFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void *) retAddressAfterSyscalls, (void *) data_trap);
    ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
    wait(&wait_status);
    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    unsigned long long oldRAX;
    //TODO: check if rax = 1, to avoid modifying syscalls that aren't WRITE
    printf("lallalarip is: %llx\n", retAddressAfterSyscalls);
    int counter = 0;
    while (regs.rip != retAddressAfterSyscalls+1 && counter < 10) {
        // manipulate syscall (redirect/copy)
        counter++;
        printf("rip is: %llx\n", regs.rip);
        oldRAX = regs.orig_rax;
//        regs.rdi = outputFile;
        ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
        ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
        wait(&wait_status);
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        // change program to call syscall again (normal)

        // listen for next syscall
    }

    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    wait(&wait_status);
    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    unsigned long test = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) regs.rip, NULL);
    printf("DBG: data at 0x%x: 0x%x\n", regs.rip, test);
    ptrace(PTRACE_POKETEXT, child_pid, (void *) retAddressAfterSyscalls, (void *) data);
    regs.rip -= 1;
    ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
    /* The child can continue running now */
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    /* Enter next system call */
//    regs.rdx = 5;
//    ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
//
//    ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
//    wait(&wait_status);
//    while (regs.rip != endRIP) {
//        ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
//        // Wait for child to stop on it's next instruction
//        wait(&wait_status);
//        // Get regs again so we have updated rip
//        old_regs = regs;
//        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
//    }

//    unsigned long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) addr, NULL);
//    printf("DBG: Original data at 0x%x: 0x%x\n", addr, data);
//
//    /* Write the trap instruction 'int 3' into the address */
//    unsigned long data_trap = (data & 0xFFFFFF00) | 0xCC;
//    ptrace(PTRACE_POKETEXT, child_pid, (void *) addr, (void *) data_trap);

    /* Let the child run to the breakpoint and wait for it to reach it */
//    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
//
//    wait(&wait_status);
//    /* See where the child is now */
//    // TODO: insert while loop for syscalls here
//    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
//    printf("DBG: Child stopped at RIP = 0x%x\n", regs.rip);
//
//    /* Remove the breakpoint by restoring the previous data and set rdx = 5 */
//    ptrace(PTRACE_POKETEXT, child_pid, (void *) addr, (void *) data);
//    regs.rip -= 1;
//    regs.rdx = 5;
//    ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
//
//    /* The child can continue running now */
//    ptrace(PTRACE_CONT, child_pid, 0, 0);

    wait(&wait_status);
    if (WIFEXITED(wait_status)) {
        printf("DBG: Child exited\n");
    } else {
        printf("DBG: Unexpected signal\n");
    }
    close(outputFile);
}

// we want to:
// 1. create a file descriptor to write the output to
// 2. begin parsing the executed program, until we reach the specified start address
// 3. set flags and destination regs accordingly
// 4. set ptrace to only break on syscalls
// 5. modify first syscall to output to our file
// 6. make program repeat that syscall again, without our intervention
// 7. when we reach the end of our debugged function, just stop debugging
void run_syscall_debugger(pid_t child_pid) {
    int wait_status;

    /* Wait for child to stop on its first instruction */
    wait(&wait_status);

    struct user_regs_struct regs;
    /* Enter next system call */
    ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
    wait(&wait_status);

    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
    regs.rdx = 5;
    ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

    /* Run system call and stop on exit */
    ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
    wait(&wait_status);

    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
    printf("DBG: the syscall returned: %d\n", regs.rax);

    /* The child can continue running now */
    ptrace(PTRACE_CONT, child_pid, 0, 0);
    wait(&wait_status);
    if (WIFEXITED(wait_status)) {
        printf("DBG: Child exited\n");
    } else {
        printf("DBG: Unexpected signal\n");
    }
}

void run_regs_override_debugger(pid_t child_pid) {
    int wait_status;

    /* Wait for child to stop on its first instruction */
    wait(&wait_status);
    while (WIFSTOPPED(wait_status)) {
        struct user_regs_struct regs;

        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        regs.rdx = 5;
        ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

        /* Make the child execute another instruction */
        if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0) {
            perror("ptrace");
            return;
        }

        /* Wait for child to stop on its next instruction */
        wait(&wait_status);
    }
}

void run_instruction_debugger(pid_t child_pid) {
    int wait_status;
    int icounter = 0;

    /* Wait for child to stop on its first instruction */
    wait(&wait_status);
    while (WIFSTOPPED(wait_status)) {
        icounter++;
        struct user_regs_struct regs;

        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        unsigned long instr = ptrace(PTRACE_PEEKTEXT, child_pid, regs.rip, NULL);

        printf("DBG: icounter = %u.  RIP = 0x%x.  instr = 0x%08x\n",
               icounter, regs.rip, instr);

        /* Make the child execute another instruction */
        if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0) {
            perror("ptrace");
            return;
        }

        /* Wait for child to stop on its next instruction */
        wait(&wait_status);
    }
}

void run_counter_debugger(pid_t child_pid) {
    int wait_status;
    int icounter = 0;

    /* Wait for child to stop on its first instruction */
    wait(&wait_status);
    while (WIFSTOPPED(wait_status)) {
        icounter++;

        /* Make the child execute another instruction */
        if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0) {
            perror("ptrace");
            return;
        }

        /* Wait for child to stop on its next instruction */
        wait(&wait_status);
    }

    printf("DBG: the child executed %d instructions\n", icounter);
}

int should_copy(const char *flag) {
    if (flag[0] == 'c') {
        // should copy, return 1
        return 1;
    }
    // should redirect
    return 0;
}

int main(int argc, char **argv) {
    pid_t child_pid;

    if (argc < 5) {
        exit(1);
    }
    unsigned long addr = strtoul(argv[1], NULL, 16);
    int copyOrRedi = should_copy(argv[2]);
//    printf("flag is: %d", copyOrRedi);
    char *outFile = argv[3];

    char args[ARG_BUF];
    for (int i = 4; i < argc - 1; ++i) {
        strcat(args, argv[i]);
        strcat(args, " ");
    }
    strcat(args, argv[argc - 1]);

//    printf("%s\n", args);

    child_pid = run_target(argv[4], args);

    // run specific "debugger"
//    int outputFile = open(outFile, O_CREAT | O_WRONLY | O_TRUNC, 0644);
//    int sz = write(outputFile, "bla\n", strlen("bla\n"));
    run_breakpoint_debugger(child_pid, addr, copyOrRedi, outFile);
//    run_counter_debugger(child_pid);
    return 0;
}