// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include "coredump.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Coredump)
#endif

void Coredump::cmd_main(void) {
    int c;
    int pid;
    std::string cppString, file_path;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    while ((c = getopt(argcnt, args, "p:")) != EOF) {
        switch(c) {
            case 'p':
                cppString.assign(optarg);
                try {
                    pid = std::stoi(cppString);
                } catch (...) {
                    fprintf(fp, "invaild pid arg %s\n",cppString.c_str());
                }
                break;
            default:
                argerrs++;
                break;
        }
    }

    if (argerrs){
        cmd_usage(pc->curcmd, SYNOPSIS);
        return;
    }

    struct task_context *tc = pid_to_context(pid);
    if (!tc) {
        fprintf(fp, "No such pid: %d\n", pid);
        return;
    }
    set_context(tc->task, NO_PID, TRUE);
    ulong task_flags = read_structure_field(tc->task,"task_struct","flags");
    if (task_flags & PF_KTHREAD) {
        fprintf(fp, "pid %d is kernel thread,not support coredump.\n", pid);
        return;
    }

    if (!tc->mm_struct) {
        fprintf(fp, "pid %d have no virtual memory space.\n", pid);
        return;
    }

    fill_thread_info(tc->thread_info);

#if defined(ARM64)
    if (field_offset(thread_info, flags) != -1){
        ulong thread_flags = read_ulong(tc->task + field_offset(task_struct, thread_info) + field_offset(thread_info, flags), "coredump task_struct thread_info flags");
        if(thread_flags & (1 << 22)){
            is_compat = true;
            if(debug){
                fprintf(fp, "is_compat: %d\n", is_compat);
            }
        }
    }

    if (machine_type(TO_CONST_STRING("ARM64"))){
        if(is_compat){
            core_ptr = std::make_shared<Compat>(swap_ptr);
        } else {
            core_ptr = std::make_shared<Arm64>(swap_ptr);
        }
    } else {
        fprintf(fp, "Not support this platform \n");
    }
#endif

#if defined(ARM)
    if (machine_type(TO_CONST_STRING("ARM"))){
        core_ptr = std::make_shared<Arm>(swap_ptr);
    } else {
        fprintf(fp, "Not support this platform \n");
    }
#endif

    core_ptr->set_core_pid(pid);

    core_ptr->parser_core_dump();

    fprintf(fp, "Coredump is Done \n");
}

Coredump::Coredump(std::shared_ptr<Swapinfo> swap) : swap_ptr(swap){
    init_command();
}

Coredump::Coredump(){
    init_command();
    swap_ptr = std::make_shared<Swapinfo>();
    //print_table();
}

void Coredump::init_command(){
    field_init(task_struct, flags);
    field_init(task_struct, thread_info);
    field_init(thread_info, flags);
    PaserPlugin::cmd_name = "coredump";
    help_str_list={
        "coredump",                            /* command name */
        "dump coredump information",        /* short description */
        "coredump -p <pid\n"
            "  This command dumps the coredump info.",
        "\n",
    };
    initialize();
}

#pragma GCC diagnostic pop
