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
#include <stdbool.h>

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
//        printf("Running the program %s with args %s\n", programname, args);
        execl(programname, args, NULL);

    } else {
        // fork error
        perror("fork");
        exit(1);
    }
}

void run_breakpoint_debugger(pid_t child_pid, unsigned long addr, int copyOrRedi, int outputFile) {
    int wait_status;
    struct user_regs_struct regs;
    struct user_regs_struct old_regs;
    /* Wait for child to stop on its first instruction */
    wait(&wait_status);
    while (WIFSTOPPED(wait_status)) {
        // Loop will run until the child process has exited
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        while (WIFSTOPPED(wait_status) && regs.rip != addr) {
            // Loop will run until the child process has reached the function address to debug from
            ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0);
            // Wait for child to stop on it's next instruction
            wait(&wait_status);
            // Get regs again so we have updated rip
            ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        }

        if (regs.rip != addr) {
            // The function address does not exist inside the assembly code
            return;
        }
        // We reached the address we want to start redirecting output from
        unsigned long rspAtCallStart = regs.rsp;
        unsigned long retAddressAfterSyscalls = ptrace(PTRACE_PEEKDATA, child_pid, (void *) rspAtCallStart, 0);

        unsigned long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) retAddressAfterSyscalls, 0);
//    printf("DBG: Original data at 0x%x: 0x%x\n", retAddressAfterSyscalls, data);

        /* Write the trap instruction 'int 3' into the address */
        unsigned long data_trap = (data & 0xFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_pid, (void *) retAddressAfterSyscalls, (void *) data_trap);

//    printf("rip where we put the breakpoint is: %llx\n", retAddressAfterSyscalls);
        retAddressAfterSyscalls += 1;

        while (WIFSTOPPED(wait_status) && regs.rip != retAddressAfterSyscalls) {
            // Break before entry to syscall
            ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
            wait(&wait_status);
            // Get regs before syscall
            ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
            if (regs.orig_rax == 1) {
                write(outputFile, "PRF:: ", 6);
                old_regs = regs;
                // manipulate syscall (redirect/copy)
                regs.rdi = outputFile;
                ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
                ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
                wait(&wait_status);
                // First write (to file) has ended
                if (copyOrRedi == 1) {
                    // should also print to screen
                    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
                    regs.rip -= 2;
                    regs.rdi = old_regs.rdi;
                    regs.rax = 1;
                    ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
                    ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
                    wait(&wait_status);
                    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
                    ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
                    wait(&wait_status);
                    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
                    ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
                    wait(&wait_status);
                    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
                } else {
                    ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
                    wait(&wait_status);
                    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
                }
            } else {
                // this is not a syscall we need to handle
                ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
                // execute syscall
                wait(&wait_status);
                ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
                // run until next syscall is hit
                wait(&wait_status);
                ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
            }
        }
        // If we exit the loop, that means the RIP has reached out breakpoint
        // need to fix the instruction to the old one
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        unsigned long fixAddr = retAddressAfterSyscalls - 1;
        unsigned long test = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) fixAddr, 0);
//    printf("DBG: data at 0x%x: 0x%x\n", regs.rip, test);
        ptrace(PTRACE_POKETEXT, child_pid, (void *) fixAddr, (void *) data);
        regs.rip -= 1;
        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
        /* The child can continue running now */
//    ptrace(PTRACE_CONT, child_pid, 0, 0);
        ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0);

        wait(&wait_status);
    }
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

    int outputFile = open(outFile, O_CREAT | O_WRONLY | O_TRUNC | O_APPEND, 0644);
//    printf("%s\n", args);

    child_pid = run_target(argv[4], args);

    // run specific "debugger"
    run_breakpoint_debugger(child_pid, addr, copyOrRedi, outputFile);

    close(outputFile);
    return 0;
}