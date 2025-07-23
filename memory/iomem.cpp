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

#include "iomem.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(IoMem)
#endif

void IoMem::cmd_main(void) {
    int c;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    if(iomem_list.size() == 0){
        parser_iomem();
    }
    while ((c = getopt(argcnt, args, "a")) != EOF) {
        switch(c) {
            case 'a':
                print_iomem(iomem_list,0);
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

void IoMem::init_offset(void) {
    field_init(resource,start);
    field_init(resource,end);
    field_init(resource,name);
    field_init(resource,flags);
    field_init(resource,parent);
    field_init(resource,sibling);
    field_init(resource,child);
    struct_init(resource);
}

void IoMem::init_command(void) {
    cmd_name = "iomem";
    help_str_list={
        "iomem",                        /* command name */
        "dump io memory information",    /* short description */
        "-a \n"
        "  This command dumps the memory layout information.",
        "\n",
        "EXAMPLES",
        "  Display io memory info:",
        "    %s> iomem -a",
        "    0x0-0xffffffff  4.00Gb     : PCI mem",
        "        0x500000-0x7fffff  3.00Mb     : 500000.pinctrl pinctrl@500000",
        "        0x1400000-0x15dffff  1.87Mb     : 1400000.clock-controller cc_base",
        "        0x1612000-0x1612003  3b         : 1613000.hsphy eud_enable_reg",
        "        0x1613000-0x161311f  287b       : 1613000.hsphy hsusb_phy_base",
        "        0x1880000-0x18de1ff  376.50Kb   : 1880000.interconnect interconnect@1880000",
        "\n",
    };
}

IoMem::IoMem(){}

void IoMem::print_iomem(std::vector<std::shared_ptr<resource>>& res_list,int level){
    std::ostringstream oss;
    for (const auto& res_ptr : res_list) {
        for (int i = 0; i < level; i++) {
            oss << "\t";
        }
        oss << std::left << std::setw(9) << csize((res_ptr->end - res_ptr->start)) << " "
            << "[" << std::hex << res_ptr->start << "~" << res_ptr->end << "] "
            << res_ptr->name << "\n";
        fprintf(fp, "%s \n",oss.str().c_str());

        if(res_ptr->childs.size() > 0){
            fprintf(fp, "%s", oss.str().c_str());
            oss.str("");
            print_iomem(res_ptr->childs,(level+1));
        }
    }
    if (!oss.str().empty()) {
        fprintf(fp, "%s", oss.str().c_str());
    }
}

void IoMem::parser_iomem(){
    if (csymbol_exists("iomem_resource")){
        parser_resource(csymbol_value("iomem_resource"),iomem_list);
    }
}

void IoMem::parser_resource(ulong addr,std::vector<std::shared_ptr<resource>>& res_list){
    if (!is_kvaddr(addr)) {
        fprintf(fp, "resource address is invalid!\n");
        return;
    }
    void *res_buf = read_struct(addr,"resource");
    if (!res_buf) {
        fprintf(fp, "Failed to read resource structure at address %lx\n", addr);
        return;
    }
    std::shared_ptr<resource> res_ptr = std::make_shared<resource>();
    res_ptr->addr = addr;
    ulong name_addr = ULONG(res_buf + field_offset(resource,name));
    res_ptr->name = read_cstring(name_addr,64, "resource_name");
    res_ptr->start = ULONG(res_buf + field_offset(resource,start));
    res_ptr->end = ULONG(res_buf + field_offset(resource,end));
    res_ptr->flags = ULONG(res_buf + field_offset(resource,flags));
    res_list.push_back(res_ptr);
    ulong sibling = ULONG(res_buf + field_offset(resource,sibling));
    if (is_kvaddr(sibling)){
        parser_resource(sibling,res_list);
    }
    ulong child = ULONG(res_buf + field_offset(resource,child));
    if (is_kvaddr(child)){
        parser_resource(child,res_ptr->childs);
    }
    FREEBUF(res_buf);
}
#pragma GCC diagnostic pop
