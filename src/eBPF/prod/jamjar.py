import datetime
from bcc import BPF
from ptrace.debugger import PtraceDebugger
import os
from collections import defaultdict
import PtraceSubroutines
import pwd
DEBUGGER = PtraceDebugger()

# ASCII art created with https://emojicombos.com/skull-ascii-art, https://emojicombos.com/mason-jar-ascii-art, https://patorjk.com/software/taag/#p=display&f=Graffiti&t=JamJar
def ascii_art():
    print(r"""
                                                        ⣴⠟⠛⠛⠛⠛⠛⠛⠛⠛⢛⣛⣻⣦
                                                        ⣿⣶⣶⡶⠀⠀⠛⠛⠋⠉⠉⠉⠉⣿
     ____                     ____                     ⠘⠿⢿⡿⠿⠿⠿⠿⠿⠿⠿⠿⢿⡿⠿⠃
    |    |____    _____      |    |____ _______        ⣠⣶⠿⠃⠀⠀⠀⠀⠀⠀⣶⡀⠘⠿⣶⣄
    |    \__  \  /     \     |    \__  \\_  __ \      ⣼⡟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⢷⣄⠈⢻⣧
/\__|    |/ __ \|  Y Y  \/\__|    |/ __ \|  | \/      ⣿⡇⠀⠀⠀⢀⣠⣤⣤⣄⡀⠀⠀⠀⣿⠀⢸⣿
\________(____  /__|_|  /\________(____  /__|         ⣿⡇⠀⠀⣴⣿⣿⣿⣿⣿⣿⣦⠀⠀⣿⠀⢸⣿
              \/      \/               \/             ⣿⡇⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⣿⠀⢸⣿
        © Jamjar v1.0                                 ⣿⡇⠀⠀⣇⠈⠉⡿⢿⠉⠁⣸⠀⠀⣿⠀⢸⣿
        by Anna Eisner, Oliver Werner,                ⣿⡇⠀⠀⠙⠛⢻⣷⣾⡟⠛⠋⠀⠀⣿⠀⢸⣿
        Jani Gabriel & Malte Schulten                 ⣿⡇⠀   ⡏  ⢹⠀⠀⠀⠀⣿⠀⢸⣿
                                                      ⢻⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠟⠀⣸⡟
                                                       ⠛⢷⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⡾⠛
    """)


# Define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE  128
#define UID_FILTER 1000

enum event_type {
    EVENT_ARG,
    EVENT_RET,
};

struct data_t {
    u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u32 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
    u32 uid;
    char comm[TASK_COMM_LEN];
    enum event_type type;
    char argv[ARGSIZE];
    int retval;
};

BPF_PERF_OUTPUT(events);

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read_user(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read_user(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid != UID_FILTER) {
        return 0;
    }

    // create data here and pass to submit_arg to save stack space (#555)
    struct data_t data = {};
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;

    __submit_arg(ctx, (void *)filename, &data);

    // skip first arg, as we submitted filename
    #pragma unroll
    for (int i = 1; i < 20; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
             goto out;
    }

    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);
out:
    return 0;
}

int do_ret_sys_execve(struct pt_regs *ctx)
{
    struct data_t data = {};
    struct task_struct *task;

    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid != UID_FILTER) {
        return 0;
    }

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = uid;

    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_RET;
    data.retval = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_text)
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
b.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")

class EventType:
    EVENT_ARG = 0
    EVENT_RET = 1

argv = defaultdict(list)

def event_handler(comm,pid,full_cmd,cwd,tty,ppid,username,target_process):
    match comm:
        case ("ls"|"rm"|"touch"):
            PtraceSubroutines.dir_routine(pid,ppid,full_cmd,cwd,target_process)
            DEBUGGER.quit()
        case ("ping"|"arp"|"ip"|"traceroute"):
            PtraceSubroutines.network_routine(pid,ppid,full_cmd,target_process)
            DEBUGGER.quit()
        case ("ps"|"kill"|"killall"):
            PtraceSubroutines.process_routine(pid,ppid,full_cmd,tty,username,target_process)
            DEBUGGER.quit()
        case _:
            print(f"[!] Subroutine for command {comm} is not implemented yet!")
            DEBUGGER.quit()

# Cleanup Commands
def cleaup_cmd(command,args):
    cmd = command.replace(b"/usr/bin/%s " % (command),b"%s"%(command)).replace(b"/usr/sbin/%s " % (command),b"%s"%(command))
    arguments = args.replace(b" --color=auto",b"").replace(b"/usr/bin/%s" % (command),b"").replace(b"/usr/sbin/%s" % (command),b"")
    fullcmd = cmd+arguments
    return fullcmd.decode(),cmd.decode()


# Print Trace and Kill Events to console
def print_event(command, cwd, uid):
    ct = str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print(f"[+][{ct}] Traced Command: [{command}]")
    print(f"\t\\--> Executed in [{cwd}] by UID [{uid}]")

def attach_ptrace(pid):
    process = DEBUGGER.addProcess(pid, False)
    return process

# Process event
def proc_event(cpu, data, size):
    event = b["events"].event(data)

    if event.type == EventType.EVENT_ARG:
        argv[event.pid].append(event.argv)
    elif event.type == EventType.EVENT_RET:
        target_process = attach_ptrace(event.pid)
        argv_text = b' '.join(argv[event.pid]).replace(b'\n', b'\\n')
        cwd = os.readlink(f"/proc/{event.pid}/cwd")
        tty = os.readlink(f"/proc/{event.pid}/fd/0").replace("/dev/","")
        username = pwd.getpwuid(event.uid).pw_name
        # Getting cleaned command
        full_command,cmd_wo_args = cleaup_cmd(event.comm,argv_text)

        # Print event to console
        print_event(full_command,cwd,event.uid)
        # Handle commands
        event_handler(cmd_wo_args,event.pid,full_command,cwd,tty,event.ppid,username,target_process)

        try:
            del(argv[event.pid])
        except Exception:
            pass


if __name__ == "__main__":
    ascii_art()

    # Loop with callback to print_event
    b["events"].open_perf_buffer(proc_event)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()
