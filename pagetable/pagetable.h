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

#ifndef PAGETABLE_DEFS_H_
#define PAGETABLE_DEFS_H_

#include "plugin.h"

#if defined(ARM64)
#include "../utils/aarch64_pagetable.h"
#else
#include "../utils/lpae_pagetable.h"
#endif

/**
 * @brief Structure representing a process page table information
 *
 * Contains information about a process's page table including PID,
 * command name, page table base address, and level information.
 */
struct process_pagetable {
    int pid;                    ///< Process ID
    std::string comm;           ///< Process command name
    ulong mm_struct;            ///< Address of mm_struct
    ulong pgd_virt;             ///< Virtual address of page global directory
    ulong pgd_phys;             ///< Physical address of page global directory
    uint levels;                ///< Number of page table levels
    bool valid;                 ///< Whether the page table is valid
};

/**
 * @brief Page Table analyzer plugin for crash utility
 *
 * This plugin provides comprehensive analysis of process page tables in the Linux kernel,
 * including virtual-to-physical address mappings, page attributes, and memory layout
 * information for debugging memory management issues.
 */
class PageTable : public ParserPlugin {
private:
    // Core data storage
    std::vector<std::shared_ptr<process_pagetable>> process_list;  ///< List of process page tables

    // Core functionality methods
    void parse_process_pagetables();                               ///< Parse process page table information
    std::shared_ptr<process_pagetable> get_process_pagetable(int pid);  ///< Get page table info for specific PID
    void print_process_pagetable(int pid);                         ///< Print page table for specific process
    void print_all_process_pagetables();                           ///< Print overview of all process page tables
    void print_ttbr_pagetable(ulong ttbr_addr);                   ///< Print page table for specified TTBR address

    // Helper methods
    bool is_valid_process_mm(ulong mm_struct);                     ///< Check if mm_struct is valid
    uint detect_pagetable_levels();                                ///< Detect page table levels from kernel config
    ulong virt_to_phys_pgd(ulong virt_addr);                      ///< Convert virtual PGD address to physical

    // Architecture detection methods
    bool is_arm64_architecture();                                  ///< Check if running on ARM64 architecture
    bool is_arm32_architecture();                                  ///< Check if running on ARM32 architecture
    bool is_lpae_enabled();                                        ///< Check if LPAE is enabled on ARM32
    void parse_and_print_pagetable(ulong pgd_phys, uint levels, const std::string& client_name); ///< Parse page table with appropriate parser

public:
    /**
     * @brief Default constructor
     */
    PageTable();

    /**
     * @brief Main command entry point - handles command line arguments
     */
    void cmd_main(void) override;

    /**
     * @brief Initialize kernel structure field offsets
     */
    void init_offset(void) override;

    /**
     * @brief Initialize command help and usage information
     */
    void init_command(void) override;

    DEFINE_PLUGIN_INSTANCE(PageTable)
};

#endif // PAGETABLE_DEFS_H_
