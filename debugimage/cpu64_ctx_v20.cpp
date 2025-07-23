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

#include "cpu64_ctx_v20.h"
#include "debugimage.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

Cpu64_Context_V20::Cpu64_Context_V20(){
    field_init(msm_dump_cpu_ctx,cpu_type);
    cpu_type_offset = field_offset(msm_dump_cpu_ctx,cpu_type);
    if (cpu_type_offset == -1){
        cpu_type_offset = 0x0;
    }
    field_init(msm_dump_cpu_ctx,ctx_type);
    ctx_type_offset = field_offset(msm_dump_cpu_ctx,ctx_type);
    if (ctx_type_offset == -1){
        ctx_type_offset = 0x4;
    }
    field_init(msm_dump_cpu_ctx,cpu_id);
    cpu_id_offset = field_offset(msm_dump_cpu_ctx,cpu_id);
    if (cpu_id_offset == -1){
        cpu_id_offset = 0xC;
    }
    field_init(msm_dump_cpu_ctx,affinity);
    cpu_index_offset = field_offset(msm_dump_cpu_ctx,affinity);
    if (cpu_index_offset == -1){
        cpu_index_offset = 0x10;
    }
    field_init(msm_dump_cpu_ctx,machine_id);
    machine_id_offset = field_offset(msm_dump_cpu_ctx,machine_id);
    if (machine_id_offset == -1){
        machine_id_offset = 0x14;
    }
    field_init(msm_dump_cpu_ctx,registers);
    registers_offset = field_offset(msm_dump_cpu_ctx,registers);
    if (registers_offset == -1){
        registers_offset = 0x20;
    }
    field_init(msm_dump_cpu_ctx,num_register_sets);
    regset_num_register_offset = field_offset(msm_dump_cpu_ctx,num_register_sets);
    if (regset_num_register_offset == -1){
        regset_num_register_offset = 0x1C;
    }
    field_init(msm_dump_cpu_register_entry,regset_id);
    regset_id_offset = field_offset(msm_dump_cpu_register_entry,regset_id);
    if (regset_id_offset == -1){
        regset_id_offset = 0x0;
    }
    field_init(msm_dump_cpu_register_entry,regset_addr);
    regset_addr_offset = field_offset(msm_dump_cpu_register_entry,regset_addr);
    if (regset_addr_offset == -1){
        regset_addr_offset = 0x8;
    }
    struct_init(msm_dump_cpu_register_entry);
    registers_size = struct_size(msm_dump_cpu_register_entry);
    if (registers_size == -1){
        registers_size = 0x10;
    }
    struct_init(msm_dump_aarch64_gprs);
    regset_size = struct_size(msm_dump_aarch64_gprs);
    if (regset_size == -1){
        regset_size = 0x110;
    }
    dump_regset_ids[0] = "MSM_DUMP_REGSET_IDS_INVALID";
    dump_regset_ids[16] = "MSM_DUMP_REGSET_IDS_AARCH64_GPRS";
    dump_regset_ids[17] = "MSM_DUMP_REGSET_IDS_AARCH64_NEON";
    dump_regset_ids[18] = "MSM_DUMP_REGSET_IDS_AARCH64_SVE";
    dump_regset_ids[19] = "MSM_DUMP_REGSET_IDS_AARCH64_SYSREGS_EL0";
    dump_regset_ids[20] = "MSM_DUMP_REGSET_IDS_AARCH64_EL1";
    dump_regset_ids[21] = "MSM_DUMP_REGSET_IDS_AARCH64_EL2";
    dump_regset_ids[22] = "MSM_DUMP_REGSET_IDS_AARCH64_VM_EL2";
    dump_regset_ids[23] = "MSM_DUMP_REGSET_IDS_AARCH64_EL3";
    dump_regset_ids[24] = "MSM_DUMP_REGSET_IDS_AARCH64_DBG_EL1";
    dump_regset_ids[25] = "MSM_DUMP_REGSET_IDS_AARCH64_CNTV_EL10";
    dump_regset_ids[26] = "MSM_DUMP_REGSET_IDS_AARCH64_CNTP_EL10";
    dump_regset_ids[27] = "MSM_DUMP_REGSET_IDS_AARCH64_CNT_EL2";
}

void Cpu64_Context_V20::compute_pc(sysdbg_cpu64_ctx_2_0_gprs_t& reg, sysdbg_cpu64_ctx_2_0_el1_t& ctx_el1_reg){
    uint64_t val = (reg.pstate >> 2) & 0x3;
    if(val == 0x0){
        reg.pc = ctx_el1_reg.elr_el1;
    } else if (val == 0x1){
        reg.pc = ctx_el1_reg.elr_el1;
    } else {
        fprintf(fp, "AArch64 PC Approximation Logic Failed! \n");
    }
}

uint32_t Cpu64_Context_V20::get_vcpu_index(uint32_t affinity) {
    uint32_t vcpu_index = 0;
    if (affinity != 0) {
        std::vector<int> aff_shift = {0, 0, 0, 0};
        uint32_t tmp_vcpu_index = affinity;
        for (size_t i = 0; i < aff_shift.size(); ++i) {
            vcpu_index |= ((tmp_vcpu_index >> (i * 8)) & 0xff) << aff_shift[i];
        }
    } else {
        vcpu_index = affinity;
    }
    return vcpu_index;
}

void Cpu64_Context_V20::print_stack(std::shared_ptr<Dump_entry> entry_ptr){
    uint32_t affinity = read_uint(entry_ptr->data_addr + cpu_index_offset, "affinity", false);
    // uint32_t cpu_type = read_uint(entry_ptr->data_addr + cpu_type_offset, "cpu_type", false);
    // uint32_t ctx_type = read_uint(entry_ptr->data_addr + ctx_type_offset, "ctx_type", false);
    uint32_t num_register = read_uint(entry_ptr->data_addr + regset_num_register_offset,"num_register",false);
    uint32_t core = get_vcpu_index(affinity);

    uint64_t registers_addr = entry_ptr->data_addr + registers_offset;
    for (uint32_t i = 0; i < num_register; i++){
        uint64_t addr = registers_addr + i * registers_size;
        uint32_t regset_id = read_uint(addr + regset_id_offset,"regset_id",false);
        if (regset_id == 0){
            continue;
        }
        std::string name = dump_regset_ids[regset_id];
        uint64_t start_addr = read_ulonglong(addr + regset_addr_offset,"regset_addr",false);
        sysdbg_cpu64_ctx_2_0_gprs_t ctx_gprs_regs;
        if(name == "MSM_DUMP_REGSET_IDS_AARCH64_GPRS") {
            if(!read_struct(start_addr, &ctx_gprs_regs, sizeof(sysdbg_cpu64_ctx_2_0_gprs_t), "sysdbg_cpu64_ctx_2_0_gprs_t", false)){
                fprintf(fp, "sysdbg_cpu64_ctx_2_0_gprs_t faild \n");
                continue;
            }
            // if(ctx_gprs_regs.pstate == 0x1){
            //     compute_pc(ctx_gprs_regs, regset_ptr->dump_ptr->ctx_el1_regs);
            // }
            uint64_t lr = ctx_gprs_regs.x[30];
            uint64_t pc = ctx_gprs_regs.pc;
            pc = pac_ignore(pc);
            ulong offset;
            struct syment *sym = value_search(pc, &offset);
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
                ulong x30 = ctx_gprs_regs.x[29] + 8;
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
        }
    }
}

void Cpu64_Context_V20::generate_cmm(std::shared_ptr<Dump_entry> entry_ptr){
    uint32_t affinity = read_uint(entry_ptr->data_addr + cpu_index_offset, "affinity", false);
    // uint32_t cpu_type = read_uint(entry_ptr->data_addr + cpu_type_offset, "cpu_type", false);
    // uint32_t ctx_type = read_uint(entry_ptr->data_addr + ctx_type_offset, "ctx_type", false);
    uint32_t num_register = read_uint(entry_ptr->data_addr + regset_num_register_offset,"num_register",false);
    uint32_t core = get_vcpu_index(affinity);
    std::string regs_file;
    if (entry_ptr->data_name.find("vcpu") != std::string::npos){
        regs_file = get_cmm_path("corevcpu" + std::to_string(core), false);
    }else{
        regs_file = get_cmm_path("core" + std::to_string(core), false);
    }
    FILE* cmmfile = fopen(regs_file.c_str(), "wb");
    if (!cmmfile) {
        fprintf(fp, "Can't open %s\n", regs_file.c_str());
        return;
    }
    uint64_t registers_addr = entry_ptr->data_addr + registers_offset;
    for (uint32_t i = 0; i < num_register; i++){
        uint64_t addr = registers_addr + i * registers_size;
        uint32_t regset_id = read_uint(addr + regset_id_offset,"regset_id",false);
        if (regset_id == 0){
            continue;
        }
        std::shared_ptr<regset_t> regset_ptr = std::make_shared<regset_t>();
        regset_ptr->id = regset_id;
        regset_ptr->name = dump_regset_ids[regset_id];
        regset_ptr->start_addr = read_ulonglong(addr + regset_addr_offset,"regset_addr",false);
        regset_ptr->end_addr = regset_ptr->start_addr + regset_size;
        regset_ptr->dump_ptr = std::make_shared<tzbsp_dump_64_2_0_t>();
        std::ostringstream oss_regs;
        switch (regset_ptr->id){
            case 16: //"MSM_DUMP_REGSET_IDS_AARCH64_GPRS"
                if(read_struct(regset_ptr->start_addr, &regset_ptr->dump_ptr->ctx_gprs_regs, sizeof(sysdbg_cpu64_ctx_2_0_gprs_t), "sysdbg_cpu64_ctx_2_0_gprs_t", false)){
                    for (size_t i = 0; i < 31; i++){
                        oss_regs << "r.s x"  << std::dec << i << " 0x" << std::hex << regset_ptr->dump_ptr->ctx_gprs_regs.x[i] << std::endl;
                    }
                    oss_regs << "r.s pc 0x"          << std::hex << regset_ptr->dump_ptr->ctx_gprs_regs.pc         << std::endl;
                    oss_regs << "r.s sp_el0 0x"      << std::hex << regset_ptr->dump_ptr->ctx_gprs_regs.sp_el0     << std::endl;
                    fwrite(oss_regs.str().c_str(), sizeof(char), oss_regs.str().size(), cmmfile);
                }else{
                    fprintf(fp, "sysdbg_cpu64_ctx_2_0_gprs_t faild \n");
                }
                break;
            case 17: //"MSM_DUMP_REGSET_IDS_AARCH64_NEON"
                if(!read_struct(regset_ptr->start_addr, &regset_ptr->dump_ptr->neon_reg, sizeof(sysdbg_neon128_registers_t), "sysdbg_neon128_registers_t", false)){
                    fprintf(fp, "sysdbg_neon128_registers_t faild \n");
                }
                break;
            case 19:  //"MSM_DUMP_REGSET_IDS_AARCH64_SYSREGS_EL0"
                if(read_struct(regset_ptr->start_addr, &regset_ptr->dump_ptr->ctx_el0_regs, sizeof(sysdbg_cpu64_ctx_2_0_el0_t), "sysdbg_cpu64_ctx_2_0_el0_t", false)){
                    oss_regs << "Data.Set SPR:0x33D02 %Quad 0x"      << std::hex << regset_ptr->dump_ptr->ctx_el0_regs.tpidr_el0      << std::endl;
                    oss_regs << "Data.Set SPR:0x33D03 %Quad 0x"      << std::hex << regset_ptr->dump_ptr->ctx_el0_regs.tpidrro_el0      << std::endl;
                    fwrite(oss_regs.str().c_str(), sizeof(char), oss_regs.str().size(), cmmfile);
                }else{
                    fprintf(fp, "sysdbg_cpu64_ctx_2_0_el0_t faild \n");
                }
                break;
            case 20:  //"MSM_DUMP_REGSET_IDS_AARCH64_EL1"
                if(read_struct(regset_ptr->start_addr, &regset_ptr->dump_ptr->ctx_el1_regs, sizeof(sysdbg_cpu64_ctx_2_0_el1_t), "sysdbg_cpu64_ctx_2_0_el1_t", false)){
                    oss_regs << "r.s sp_el1 0x" << std::hex << regset_ptr->dump_ptr->ctx_el1_regs.sp_el1 << std::endl;
                    oss_regs << "r.s elr_el1 0x" << std::hex << regset_ptr->dump_ptr->ctx_el1_regs.elr_el1 << std::endl;
                    oss_regs << "r.s spsr_el1 0x" << std::hex << regset_ptr->dump_ptr->ctx_el1_regs.spsr_el1 << std::endl;
                    oss_regs << "Data.Set SPR:0x30102 %Quad 0x" << std::hex << regset_ptr->dump_ptr->ctx_el1_regs.cpacr_el1 << std::endl;
                    oss_regs << "Data.Set SPR:0x32000 %Quad 0x" << std::hex << regset_ptr->dump_ptr->ctx_el1_regs.csselr_el1 << std::endl;
                    oss_regs << "Data.Set SPR:0x30520 %Quad 0x" << std::hex << regset_ptr->dump_ptr->ctx_el1_regs.esr_el1  << std::endl;
                    oss_regs << "Data.Set SPR:0x30600 %Quad 0x" << std::hex << regset_ptr->dump_ptr->ctx_el1_regs.far_el1 << std::endl;
                    oss_regs << "Data.Set SPR:0x30C10 %Quad 0x" << std::hex << regset_ptr->dump_ptr->ctx_el1_regs.isr_el1 << std::endl;
                    oss_regs << "Data.Set SPR:0x30740 %Quad 0x" << std::hex << regset_ptr->dump_ptr->ctx_el1_regs.par_el1 << std::endl;
                    oss_regs << "Data.Set SPR:0x30A20 %Quad 0x" << std::hex << regset_ptr->dump_ptr->ctx_el1_regs.mair_el1 << std::endl;
                    oss_regs << "Data.Set SPR:0x30100 %Quad 0x" << std::hex << regset_ptr->dump_ptr->ctx_el1_regs.sctlr_el1 << std::endl;
                    oss_regs << "Data.Set SPR:0x30202 %Quad 0x" << std::hex << regset_ptr->dump_ptr->ctx_el1_regs.tcr_el1 << std::endl;
                    oss_regs << "Data.Set SPR:0x30D04 %Quad 0x" << std::hex << regset_ptr->dump_ptr->ctx_el1_regs.tpidr_el1 << std::endl;
                    oss_regs << "Data.Set SPR:0x30200 %Quad 0x" << std::hex << regset_ptr->dump_ptr->ctx_el1_regs.ttbr0_el1 << std::endl;
                    oss_regs << "Data.Set SPR:0x30201 %Quad 0x" << std::hex << regset_ptr->dump_ptr->ctx_el1_regs.ttbr1_el1 << std::endl;
                    oss_regs << "Data.Set SPR:0x30C00 %Quad 0x" << std::hex << regset_ptr->dump_ptr->ctx_el1_regs.vbar_el1 << std::endl;
                    fwrite(oss_regs.str().c_str(), sizeof(char), oss_regs.str().size(), cmmfile);
                }else{
                    fprintf(fp, "sysdbg_cpu64_ctx_2_0_el1_t faild \n");
                }
                break;
            case 22:  //"MSM_DUMP_REGSET_IDS_AARCH64_VM_EL2"
                if(read_struct(regset_ptr->start_addr, &regset_ptr->dump_ptr->vm_regs, sizeof(sysdbg_cpu64_vm_el2_ctx_2_0_t), "sysdbg_cpu64_vm_el2_ctx_2_0_t", false)){
                    oss_regs << "Data.Set SPR:0x34112 %Quad 0x" << std::hex << regset_ptr->dump_ptr->vm_regs.cptr_el2 << std::endl;
                    oss_regs << "Data.Set SPR:0x34110 %Quad 0x" << std::hex << regset_ptr->dump_ptr->vm_regs.hcr_el2 << std::endl;
                    oss_regs << "Data.Set SPR:0x34111 %Quad 0x" << std::hex << regset_ptr->dump_ptr->vm_regs.mdcr_el2 << std::endl;
                    oss_regs << "Data.Set SPR:0x34212 %Quad 0x" << std::hex << regset_ptr->dump_ptr->vm_regs.vtcr_el2 << std::endl;
                    oss_regs << "Data.Set SPR:0x34210 %Quad 0x" << std::hex << regset_ptr->dump_ptr->vm_regs.vttbr_el2 << std::endl;
                    fwrite(oss_regs.str().c_str(), sizeof(char), oss_regs.str().size(), cmmfile);
                }else{
                    fprintf(fp, "sysdbg_cpu64_vm_el2_ctx_2_0_t faild \n");
                }
                break;
            case 25:  //"MSM_DUMP_REGSET_IDS_AARCH64_CNTV_EL10"
                if(read_struct(regset_ptr->start_addr, &regset_ptr->dump_ptr->cntv_regs, sizeof(sysdbg_cpu64_cntv_el10_ctx_2_0_t), "sysdbg_cpu64_cntv_el10_ctx_2_0_t", false)){
                    oss_regs << "Data.Set SPR:0x30E10 %Quad 0x" << std::hex << regset_ptr->dump_ptr->cntv_regs.cntkctl_el1 << std::endl;
                    oss_regs << "Data.Set SPR:0x33E31 %Quad 0x" << std::hex << regset_ptr->dump_ptr->cntv_regs.cntv_ctl_el0 << std::endl;
                    oss_regs << "Data.Set SPR:0x33E32 %Quad 0x" << std::hex << regset_ptr->dump_ptr->cntv_regs.cntv_cval_el0 << std::endl;
                    oss_regs << "Data.Set SPR:0x33E30 %Quad 0x" << std::hex << regset_ptr->dump_ptr->cntv_regs.cntv_tval_el0 << std::endl;
                    fwrite(oss_regs.str().c_str(), sizeof(char), oss_regs.str().size(), cmmfile);
                }else{
                    fprintf(fp, "sysdbg_cpu64_cntv_el10_ctx_2_0_t faild \n");
                }
                break;
            case 26:  //"MSM_DUMP_REGSET_IDS_AARCH64_CNTP_EL10"
                if(read_struct(regset_ptr->start_addr, &regset_ptr->dump_ptr->cntp_regs, sizeof(sysdbg_cpu64_cntp_el10_ctx_2_0_t), "sysdbg_cpu64_cntp_el10_ctx_2_0_t", false)){
                    oss_regs << "Data.Set SPR:0x33E21 %Quad 0x" << std::hex << regset_ptr->dump_ptr->cntp_regs.cntp_ctl_el0 << std::endl;
                    oss_regs << "Data.Set SPR:0x33E22 %Quad 0x" << std::hex << regset_ptr->dump_ptr->cntp_regs.cntp_cval_el0 << std::endl;
                    oss_regs << "Data.Set SPR:0x33E20 %Quad 0x" << std::hex << regset_ptr->dump_ptr->cntp_regs.cntp_tval_el0 << std::endl;
                    fwrite(oss_regs.str().c_str(), sizeof(char), oss_regs.str().size(), cmmfile);
                }else{
                    fprintf(fp, "sysdbg_cpu64_cntp_el10_ctx_2_0_t faild \n");
                }
                break;
            case 27:  //"MSM_DUMP_REGSET_IDS_AARCH64_CNT_EL2"
                if(!read_struct(regset_ptr->start_addr, &regset_ptr->dump_ptr->cnt_regs, sizeof(sysdbg_cpu64_cnt_el2_ctx_2_0_t), "sysdbg_cpu64_cnt_el2_ctx_2_0_t", false)){
                    fprintf(fp, "sysdbg_cpu64_cnt_el2_ctx_2_0_t faild \n");
                }
                break;
            default:
                break;
        }
        if(regset_ptr->dump_ptr->ctx_gprs_regs.pstate == 0x1){
            compute_pc(regset_ptr->dump_ptr->ctx_gprs_regs, regset_ptr->dump_ptr->ctx_el1_regs);
            fprintf(fp, "Need re-compute_pc \n");
        }
    }
    fclose(cmmfile);
    fprintf(fp, "save to %s\n", regs_file.c_str());
}

#pragma GCC diagnostic pop
