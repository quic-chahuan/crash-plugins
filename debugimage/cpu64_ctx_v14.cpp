/**
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "cpu64_ctx_v14.h"
#include "debugimage.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

Cpu64_Context_V14::Cpu64_Context_V14(){

}

void Cpu64_Context_V14::compute_pc(sysdbg_cpu64_ctx_1_4_t reg,sysdbg_neon128_registers_t neon_reg){
    // PC is invalid
    if (reg.cpu_state0 == 1){
        uint64_t orig_pc = reg.pc;
        if ((reg.cpu_state1 & (1ULL << 4)) != 0) { // AArch32 Mode
            uint64_t val = reg.cpu_state1 & 0xF;
            if (val == 0x0 && (reg.cpu_state3 & (1ULL << 14)) != 0){
                reg.pc = reg.x[14];
            }else if (val == 0x1 && (reg.cpu_state3 & (1ULL << 30)) != 0){
                reg.pc = reg.x[30];
            }else if (val == 0x2 && (reg.cpu_state3 & (1ULL << 16)) != 0){
                reg.pc = reg.x[16];
            }else if (val == 0x3 && (reg.cpu_state3 & (1ULL << 18)) != 0){
                reg.pc = reg.x[18];
            }else if (val == 0x7 && (reg.cpu_state3 & (1ULL << 20)) != 0){
                reg.pc = reg.x[20];
            }else if (val == 0xB && (reg.cpu_state3 & (1ULL << 22)) != 0){
                reg.pc = reg.x[22];
            }else if (val == 0x6 && (reg.cpu_state5 & (1ULL << 31)) != 0){
                reg.pc = neon_reg.v31_upper;
            }else if (val == 0xA ){
                reg.pc = reg.elr_el2;
            }else if (val == 0xF && (reg.cpu_state3 & (1ULL << 14)) != 0){
                reg.pc = reg.x[14];
            }else{
                fprintf(fp, "AArch32 PC Approximation Logic Failed! \n");
            }
        }else{// AArch64 Mode
            if ((reg.cpu_state3 & (1ULL << 30)) != 0){
                reg.pc = reg.x[30];
            }
            uint64_t val = (reg.cpu_state1 >> 2) & 0x3;
            if (val == 0x0){
                reg.pc = reg.elr_el1;
            }else if (val == 0x1){
                reg.pc = reg.elr_el1;
            }else if (val == 0x2){
                reg.pc = reg.elr_el2;
            }else if (val == 0x3){
                reg.pc = reg.elr_el3;
            }else{
                fprintf(fp, "AArch64 PC Approximation Logic Failed! \n");
            }
        }
        if (orig_pc && orig_pc != reg.pc){
            fprintf(fp, "PC computed by SDI and Parser are different \n");
        }
    }
}

void Cpu64_Context_V14::print_stack(std::shared_ptr<Dump_entry> entry_ptr){
    int core = entry_ptr->id - DATA_CPU_CTX;
    void* buf = read_memory(entry_ptr->data_addr,sizeof(tzbsp_dump_64_1_4_t),"tzbsp_dump_64_1_4_t",false);
    tzbsp_dump_64_1_4_t reg_dump = *reinterpret_cast<tzbsp_dump_64_1_4_t*>(buf);

    uint64_t lr = reg_dump.sc_regs.x[30];
    uint64_t pc = pac_ignore(reg_dump.sc_regs.pc);
    struct syment *sym;
    ulong offset;
    sym = value_search(pc, &offset);
    std::ostringstream oss;
    oss << "Core" << std::dec << core << " " << "\n";
    if (sym) {
        oss << "PC: " << "<" << std::hex << pc << ">: " << sym->name  << "+" << std::hex << offset << "\n";
    } else {
        oss << "PC: " << "<" << std::hex << pc << ">: " << "UNKNOWN"  << "+" << std::hex << 0 << "\n";
    }

    lr = pac_ignore(lr);
    sym = value_search(lr, &offset);
    if (sym) {
        oss << "LR: " << "<" << std::hex << lr << ">: " << sym->name  << "+" << std::hex << offset << "\n";
    } else {
        oss << "LR: " << "<" << std::hex << lr << ">: " << "UNKNOWN"  << "+" << std::hex << 0 << "\n";
    }
    fprintf(fp, "%s \n",oss.str().c_str());
#if defined(ARM64)
    struct task_context *tc;
    tc = task_to_context(tt->active_set[core]);
    if(tc){
        ulong stackbase = GET_STACKBASE(tc->task);
        ulong stacktop = GET_STACKTOP(tc->task);
        ulong x30 = reg_dump.sc_regs.x[29] + 8;
        if ((x30 > stackbase && x30 < stacktop)){
            uwind_task_back_trace(tc->pid, x30);
        }

        ulong cpu_irq_stack = machdep->machspec->irq_stacks[core];
        if ((x30 > cpu_irq_stack && x30 < (cpu_irq_stack + machdep->machspec->irq_stack_size))){
            uwind_irq_back_trace(core,x30);
        }
        fprintf(fp, "\n");
    }
#endif
    FREEBUF(buf);
}

void Cpu64_Context_V14::generate_cmm(std::shared_ptr<Dump_entry> entry_ptr){
    void* buf = (tzbsp_dump_64_1_4_t*)read_memory(entry_ptr->data_addr,sizeof(tzbsp_dump_64_1_4_t),"tzbsp_dump_64_1_4_t",false);
    tzbsp_dump_64_1_4_t reg_dump = *reinterpret_cast<tzbsp_dump_64_1_4_t*>(buf);
    int core = entry_ptr->id - DATA_CPU_CTX;
    compute_pc(reg_dump.sc_regs,reg_dump.neon_reg);
    std::string regs_file = get_cmm_path("core" + std::to_string(core), false);
    FILE* cmmfile = fopen(regs_file.c_str(), "wb");
    if (!cmmfile) {
        fprintf(fp, "Can't open %s\n", regs_file.c_str());
        FREEBUF(buf);
        return;
    }
    std::ostringstream oss_regs;
    for (size_t i = 0; i < 31; i++){
        oss_regs << "r.s x"  << std::dec << i << " 0x" << std::hex << reg_dump.sc_regs.x[i] << std::endl;
    }
    oss_regs << "r.s pc 0x"          << std::hex << reg_dump.sc_regs.pc         << std::endl;
    oss_regs << "r.s sp_el3 0x"      << std::hex << reg_dump.sc_regs.sp_el3     << std::endl;
    oss_regs << "r.s elr_el3 0x"     << std::hex << reg_dump.sc_regs.elr_el3    << std::endl;
    oss_regs << "r.s spsr_el3 0x"    << std::hex << reg_dump.sc_regs.spsr_el3   << std::endl;
    oss_regs << "r.s sp_el2 0x"      << std::hex << reg_dump.sc_regs.sp_el2     << std::endl;
    oss_regs << "r.s elr_el2 0x"     << std::hex << reg_dump.sc_regs.elr_el2    << std::endl;
    oss_regs << "r.s spsr_el2 0x"    << std::hex << reg_dump.sc_regs.spsr_el2   << std::endl;
    oss_regs << "r.s sp_el1 0x"      << std::hex << reg_dump.sc_regs.sp_el1     << std::endl;
    oss_regs << "r.s elr_el1 0x"     << std::hex << reg_dump.sc_regs.elr_el1    << std::endl;
    oss_regs << "r.s spsr_el1 0x"    << std::hex << reg_dump.sc_regs.spsr_el1   << std::endl;
    oss_regs << "r.s sp_el0 0x"      << std::hex << reg_dump.sc_regs.sp_el0     << std::endl;
    fwrite(oss_regs.str().c_str(), sizeof(char), oss_regs.str().size(), cmmfile);
    fclose(cmmfile);

    compute_pc(reg_dump.sc_secure,reg_dump.neon_reg);
    std::string secure_file = get_cmm_path("core" + std::to_string(core), true);
    cmmfile = fopen(secure_file.c_str(), "wb");
    if (!cmmfile) {
        fprintf(fp, "Can't open %s\n", secure_file.c_str());
        FREEBUF(buf);
        return;
    }
    std::ostringstream oss_secure;
    for (size_t i = 0; i < 31; i++){
        oss_secure << "r.s x"  << std::dec << i << " 0x" << std::hex << reg_dump.sc_secure.x[i] << std::endl;
    }
    oss_secure << "r.s pc 0x"          << std::hex << reg_dump.sc_secure.pc         << std::endl;
    oss_secure << "r.s sp_el3 0x"      << std::hex << reg_dump.sc_secure.sp_el3     << std::endl;
    oss_secure << "r.s elr_el3 0x"     << std::hex << reg_dump.sc_secure.elr_el3    << std::endl;
    oss_secure << "r.s spsr_el3 0x"    << std::hex << reg_dump.sc_secure.spsr_el3   << std::endl;
    oss_secure << "r.s sp_el2 0x"      << std::hex << reg_dump.sc_secure.sp_el2     << std::endl;
    oss_secure << "r.s elr_el2 0x"     << std::hex << reg_dump.sc_secure.elr_el2    << std::endl;
    oss_secure << "r.s spsr_el2 0x"    << std::hex << reg_dump.sc_secure.spsr_el2   << std::endl;
    oss_secure << "r.s sp_el1 0x"      << std::hex << reg_dump.sc_secure.sp_el1     << std::endl;
    oss_secure << "r.s elr_el1 0x"     << std::hex << reg_dump.sc_secure.elr_el1    << std::endl;
    oss_secure << "r.s spsr_el1 0x"    << std::hex << reg_dump.sc_secure.spsr_el1   << std::endl;
    oss_secure << "r.s sp_el0 0x"      << std::hex << reg_dump.sc_secure.sp_el0     << std::endl;
    fwrite(oss_secure.str().c_str(), sizeof(char), oss_secure.str().size(), cmmfile);
    fclose(cmmfile);
    fprintf(fp, "save to %s\n", regs_file.c_str());
    FREEBUF(buf);
}

#pragma GCC diagnostic pop
