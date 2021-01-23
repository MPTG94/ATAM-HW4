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

unsigned long put_breakpoint_and_get_original_instruction(pid_t child_pid, unsigned long addr) {
    unsigned long orig_instr = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) addr, 0);
    /* Write the trap instruction 'int 3' into the address */
    unsigned long data_trap = (orig_instr & 0xFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void *) addr, (void *) data_trap);
    return orig_instr;
}

struct user_regs_struct
remove_breakpoint_set_original_line_and_decrease_rip(pid_t child_pid, unsigned long addr, unsigned long orig_instr, struct user_regs_struct *regs) {
    ptrace(PTRACE_GETREGS, child_pid, 0, regs);

    ptrace(PTRACE_POKETEXT, child_pid, (void *) addr, (void *) orig_instr);
    (*regs).rip -= 1;
    ptrace(PTRACE_SETREGS, child_pid, 0, regs);
    return (*regs);
}

void run_breakpoint_debugger(pid_t child_pid, unsigned long addr, int copyOrRedi, int outputFile) {
    int wait_status;
    struct user_regs_struct regs;
    struct user_regs_struct old_regs;
    wait(&wait_status);
    /* Wait for child to stop on its first instruction */
    unsigned long orig_instr_add_debug_addr = put_breakpoint_and_get_original_instruction(child_pid, addr);
    while (WIFSTOPPED(wait_status)) {
        ptrace(PTRACE_CONT, child_pid, 0, 0);
        wait(&wait_status);
        // Loop will run until the child process has exited
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        regs = remove_breakpoint_set_original_line_and_decrease_rip(child_pid, addr, orig_instr_add_debug_addr, &regs);

        // We reached the address we want to start redirecting output from
        // The RIP when we exit the debugged function
        unsigned long return_line_num = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) regs.rsp, 0);

        unsigned long long int original_rsp_value = regs.rsp;
        // The original line where we placed the breakpoint at the exit of the debugged function
        unsigned long original_return_line = put_breakpoint_and_get_original_instruction(child_pid, return_line_num);
        ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
        bool should_stop = false;
        while (!should_stop) {
            wait(&wait_status);
            if (!WIFSTOPPED(wait_status)) {
                should_stop = true;
            }
            ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
            unsigned long rsp_diff = regs.rsp - original_rsp_value;
            if (regs.rip == return_line_num + 1 && rsp_diff == 8) {
                ptrace(PTRACE_POKETEXT, child_pid, (void *) return_line_num, (void *) original_return_line);
                regs.rip -= 1;
                put_breakpoint_and_get_original_instruction(addr, child_pid);
                ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
                should_stop = true;
            } else if (regs.orig_rax == 1) {
                write(outputFile, "PRF:: ", 6);
                ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
                old_regs = regs;
                if (copyOrRedi == 0) {
                    int rdi_backup = regs.rdi;
                    regs.rdi = outputFile;
                    ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
                    ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
                    wait(&wait_status);
                    regs.rdi = rdi_backup;
                    ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
                } else {
                    int msg_len = (int) regs.rdx;
                    char msg[msg_len];
                    for (int i = 0; i < msg_len; ++i) {
                        msg[i] = ptrace(PTRACE_PEEKTEXT, child_pid, (void *) regs.rsi + i, NULL);
                    }
                    write(outputFile, msg, msg_len);
                    ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
                    wait(&wait_status);
                }
                regs = old_regs;
                ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
                ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
            } else {
                ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
                wait(&wait_status);
                ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
            }
        }
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

    int outputFile = open(outFile, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (outputFile < 0) {
        exit(1);
    }
//    printf("%s\n", args);

    child_pid = run_target(argv[4], args);

    // run specific "debugger"
    run_breakpoint_debugger(child_pid, addr, copyOrRedi, outputFile);

    if (close(outputFile) < 0) {
        exit(1);
    }

    return 0;
}