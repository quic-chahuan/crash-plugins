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

#include "cma.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Cma)
#endif

void Cma::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    if (mem_list.size() == 0){
        parser_cma_areas();
    }
    while ((c = getopt(argcnt, args, "au:f:")) != EOF) {
        switch(c) {
            case 'a':
                print_cma_areas();
                break;
            case 'u':
                cppString.assign(optarg);
                print_cma_page_status(cppString,true);
                break;
            case 'f':
                cppString.assign(optarg);
                print_cma_page_status(cppString,false);
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

void Cma::init_offset(void) {
    field_init(cma,base_pfn);
    field_init(cma,count);
    field_init(cma,bitmap);
    field_init(cma,order_per_bit);
    field_init(cma,name);
    struct_init(cma);
}

void Cma::init_command(void) {
    cmd_name = "cma";
    help_str_list={
        "cma",                            /* command name */
        "dump cma information",        /* short description */
        "-a \n"
            "  cma -u <cma name>\n"
            "  cma -f <cma name>\n"
            "  This command dumps the cma info.",
        "\n",
        "EXAMPLES",
        "  Display cma memory info:",
        "    %s> cma -a",
        "    ==============================================================================================================",
        "    [1]mem_dump_region            cma:0xffffffde315f35a8 PFN:0xbf800~0xc0000       size:8.00Mb     used:0b         order:0",
        "    [2]user_contig_region         cma:0xffffffde315f3668 PFN:0xbe800~0xbf800       size:16.00Mb    used:0b         order:0",
        "    [3]adsp_region                cma:0xffffffde315f3728 PFN:0xbe000~0xbe800       size:8.00Mb     used:2.20Mb     order:0",
        "    [4]linux,cma                  cma:0xffffffde315f37e8 PFN:0xbc000~0xbe000       size:32.00Mb    used:12.38Mb    order:0",
        "    ==============================================================================================================",
        "    Total:264.00Mb allocated:15.77Mb",
        "\n",
        "  Display the allocted pages of specified cma region by cma name:",
        "    %s> cma -u adsp_region",
        "    ========================================================================",
        "    name           : adsp_region",
        "    base_pfn       : 0xbe000",
        "    end_pfn        : 0xbe800",
        "    count          : 2048",
        "    size           : 0x2000",
        "    bitmap         : 0xffffff8006986900 ~ 0xffffff8006986a00",
        "    ========================================================================",
        "    [1]PFN:0xbe000 paddr:0xbe000000 page:0xfffffffe01f80000 allocted",
        "    [2]PFN:0xbe001 paddr:0xbe001000 page:0xfffffffe01f80040 allocted",
        "    [3]PFN:0xbe002 paddr:0xbe002000 page:0xfffffffe01f80080 allocted",
        "    [4]PFN:0xbe003 paddr:0xbe003000 page:0xfffffffe01f800c0 allocted",
        "\n",
        "  Display the free pages of specified cma region by cma name:",
        "    %s> cma -f adsp_region",
        "    ========================================================================",
        "    name           : adsp_region",
        "    base_pfn       : 0xbe000",
        "    end_pfn        : 0xbe800",
        "    count          : 2048",
        "    size           : 0x2000",
        "    bitmap         : 0xffffff8006986900 ~ 0xffffff8006986a00",
        "    ========================================================================",
        "    [1]PFN:0xbe032 paddr:0xbe032000 page:0xfffffffe01f80c80 free",
        "    [2]PFN:0xbe033 paddr:0xbe033000 page:0xfffffffe01f80cc0 free",
        "    [3]PFN:0xbe034 paddr:0xbe034000 page:0xfffffffe01f80d00 free",
        "\n",
    };
}

Cma::Cma(){}

void Cma::parser_cma_areas(){
    if (!csymbol_exists("cma_areas")){
        fprintf(fp, "cma_areas doesn't exist in this kernel!\n");
        return;
    }
    ulong cma_areas_addr = csymbol_value("cma_areas");
    if (!is_kvaddr(cma_areas_addr)) {
        fprintf(fp, "cma_areas address is invalid!\n");
        return;
    }
    ulong cma_area_count = read_ulong(csymbol_value("cma_area_count"),"cma_area_count");
    if (cma_area_count == 0) {
        fprintf(fp, "cma_area_count is zero!\n");
        return;
    }
    for (ulong i = 0; i < cma_area_count; ++i) {
        ulong cma_addr = cma_areas_addr + i * struct_size(cma);
        void *cma_buf = read_struct(cma_addr,"cma");
        if (!cma_buf) {
            fprintf(fp, "Failed to read cma structure at address %lx\n", cma_addr);
            continue;
        }
        std::shared_ptr<cma_mem> cma_ptr = std::make_shared<cma_mem>();
        cma_ptr->addr = cma_addr;
        cma_ptr->base_pfn = ULONG(cma_buf + field_offset(cma,base_pfn));
        cma_ptr->count = ULONG(cma_buf + field_offset(cma,count));
        cma_ptr->bitmap = ULONG(cma_buf + field_offset(cma,bitmap));
        cma_ptr->order_per_bit = UINT(cma_buf + field_offset(cma,order_per_bit));
        // read cma name
        if (THIS_KERNEL_VERSION >= LINUX(5,10,0)){
            char cma_name[64];
            memcpy(cma_name,cma_buf + field_offset(cma,name),64);
            cma_ptr->name = cma_name;
        }else{
            ulong name_addr = ULONG(cma_buf + field_offset(cma,name));
            cma_ptr->name = read_cstring(name_addr,64, "cma_name");
        }
        cma_ptr->allocated_size = get_cma_used_size(cma_ptr);
        FREEBUF(cma_buf);
        mem_list.push_back(cma_ptr);
    }
}

void Cma::print_cma_areas(){
    ulong totalcma_pages = 0;
    ulong total_use = 0;
    std::ostringstream oss;
    oss << "=====================================================================================================\n";
    int index = 1;
    size_t max_len = 0;
    size_t addr_len = 0;
    for (const auto& cma : mem_list) {
        max_len = std::max(max_len,cma->name.size());
        std::stringstream tmp;
        tmp << std::hex << (cma->base_pfn << 12);
        addr_len = std::max(addr_len,tmp.str().length());
    }
    oss << std::left << std::setw(max_len)                   << "Name" << " "
        << std::left << std::setw(VADDR_PRLEN)               << "cma" << " "
        << std::left << std::setw(addr_len * 2 + 3)          << "Range" << " "
        << std::left << std::setw(10)                        << "Size" << " "
        << std::left << std::setw(10)                        << "Used" << " "
        << std::left << "Order" << " \n";
    for (const auto& cma : mem_list) {
        totalcma_pages += cma->count;
        total_use += cma->allocated_size;
        oss << std::left << std::setw(max_len)  << cma->name << " "
            << std::left << std::hex  << std::setw(VADDR_PRLEN)   << cma->addr << " "
            << std::right << "[" << std::hex  << std::setw(addr_len) << std::setfill('0') << (cma->base_pfn << 12)
            << "~"
            << std::right << std::hex  << std::setw(addr_len) << std::setfill('0') << ((cma->base_pfn + cma->count) << 12) << "]" << " "
            << std::left << std::setw(10) << std::setfill(' ') << csize(cma->count * page_size) << " "
            << std::left << std::setw(10) << csize(cma->allocated_size) << " "
            << cma->order_per_bit << " \n";
        index += 1;
    }
    oss << "=====================================================================================================\n";
    oss << "Total:" << csize(totalcma_pages * page_size) << " ";
    oss << "allocated:" << csize(total_use) << "\n";
    fprintf(fp, "%s", oss.str().c_str());
}

int Cma::get_cma_used_size(std::shared_ptr<cma_mem> cma){
    // calc how many byte of bitmap
    size_t nr_byte = (cma->count >> cma->order_per_bit) / 8;
    size_t per_bit_size = (1U << cma->order_per_bit) * page_size;
    size_t used_count = 0;
    ulong bitmap_addr = cma->bitmap;
    for (size_t i = 0; i < nr_byte; ++i) {
        unsigned char bitmap_data = read_byte(bitmap_addr,"cma bitmap");
        std::bitset<8> bits(bitmap_data);
        size_t nr_bit = bits.count();
        // fprintf(fp, "bitmap_addr:%#lx bitmap:%x, nr_bit:%d\n",bitmap_addr, bitmap_data, nr_bit);
        used_count += nr_bit;
        bitmap_addr += 1;
    }
    return (used_count * per_bit_size);
}

void Cma::print_cma_page_status(std::string name,bool alloc){
    std::ostringstream oss;
    for (const auto& cma : mem_list) {
        if (cma->name.find(name) != std::string::npos) {
            oss << "\n========================================================================\n";
            oss << std::left << std::setw(10) << "Name"     << ": " << cma->name << "\n"
                << std::left << std::setw(10) << "Base_pfn" << ": " << std::hex << cma->base_pfn << "\n"
                << std::left << std::setw(10) << "End_pfn"  << ": " << std::hex << (cma->base_pfn + cma->count) << "\n"
                << std::left << std::setw(10) << "Count"    << ": " << std::dec << cma->count << "\n"
                << std::left << std::setw(10) << "Size"     << ": " << csize(cma->count * page_size) << "\n";
            // calc how many byte of bitmap
            size_t nr_byte = (cma->count >> cma->order_per_bit) / 8;
            oss << std::left << std::setw(10) << "Bitmap" << ": "
                << std::hex << cma->bitmap
                << " ~ "
                << std::hex << (cma->bitmap + nr_byte) << "\n";

            oss << "========================================================================\n";
            // calc how many page of one bit
            size_t nr_pages = (1U << cma->order_per_bit);
            ulong bitmap_addr = cma->bitmap;
            int index = 1;
            for (size_t i = 0; i < nr_byte; i++){
                unsigned char bitmap_data = read_byte(bitmap_addr,"cma bitmap");
                for (size_t j = 0; j < 8; j++){ //bit of one byte
                    int bit_offset = i * 8 + j;
                    ulong base_pfn = cma->base_pfn + bit_offset * nr_pages;
                    bool bit_value = (((bitmap_data >> j) & 0x1) ? true:false);
                    for (size_t k = 0; k < nr_pages; k++){
                        ulong pfn = base_pfn + k;
                        physaddr_t paddr = pfn << 12;
                        ulong page = 0;
                        if (phys_to_page(paddr, &page) && bit_value == alloc) {
                            oss << "[" << std::setw(5) << std::setfill('0') << index << "]"
                                << "Pfn:"   << std::setfill(' ') << std::hex << pfn << " "
                                << "Page:"  << std::hex << (ulonglong)page << " "
                                << "paddr:" << std::hex << (ulonglong)paddr << " "
                                << (bit_value ? "allocted":"free") << "\n";
                            index += 1;
                        }
                    }
                }
                bitmap_addr += 1;
            }
        }
    }
    fprintf(fp, "%s", oss.str().c_str());
}

#pragma GCC diagnostic pop
