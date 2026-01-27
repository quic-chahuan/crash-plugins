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

#include "pagetable.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(PageTable)
#endif

/**
 * @brief Main command entry point for Page Table analysis
 *
 * Parses command line arguments and dispatches to appropriate handler functions:
 * -a: Display all process page tables overview
 * -p <pid>: Show detailed page table for specific process
 */
void PageTable::cmd_main(void) {
    // Check minimum argument count
    if (argcnt < 2) {
        LOGD("Insufficient arguments provided, showing usage\n");
        cmd_usage(pc->curcmd, SYNOPSIS);
        return;
    }

    int argerrs = 0;
    int c;

    // Parse command line options
    while ((c = getopt(argcnt, args, "ap:t:")) != EOF) {
        switch(c) {
            case 'a':
                LOGD("Executing print_all_process_pagetables() - display all process page tables\n");
                print_all_process_pagetables();
                break;
            case 'p':
                if (optarg) {
                    int pid = std::stoi(optarg);
                    LOGD("Executing print_process_pagetable(%d) - display page table for PID %d\n", pid, pid);
                    print_process_pagetable(pid);
                } else {
                    LOGE("Error: -p option requires a PID argument\n");
                    argerrs++;
                }
                break;
            case 't':
                if (optarg) {
                    ulong ttbr_addr = std::stoul(optarg, nullptr, 16);
                    LOGD("Executing print_ttbr_pagetable(0x%lx) - display page table for TTBR 0x%lx\n", ttbr_addr, ttbr_addr);
                    print_ttbr_pagetable(ttbr_addr);
                } else {
                    LOGE("Error: -t option requires a TTBR address argument (in hex)\n");
                    argerrs++;
                }
                break;
            default:
                LOGD("Unknown option: -%c\n", c);
                argerrs++;
                break;
        }
    }

    // Handle argument errors
    if (argerrs) {
        LOGE("Command line argument errors detected: %d\n", argerrs);
        cmd_usage(pc->curcmd, SYNOPSIS);
        return;
    }
}

/**
 * @brief Initialize kernel structure field offsets
 *
 * Sets up field offsets for memory management structures used in page table analysis.
 */
void PageTable::init_offset(void) {
    // Initialize memory management structure field offsets
    field_init(mm_struct, pgd);
    field_init(mm_struct, mmap);
    field_init(mm_struct, mm_users);
    field_init(mm_struct, mm_count);
    field_init(task_struct, mm);
    field_init(task_struct, pid);
    field_init(task_struct, comm);
}

/**
 * @brief Initialize command help and usage information
 *
 * Sets up the command name, description, and detailed help text including
 * usage examples and expected output formats for the PageTable plugin.
 */
void PageTable::init_command(void) {
    cmd_name = "pagetable";
    help_str_list = {
        "pagetable",
        "display process page table information",
        "[-a] [-p <pid>] [-t <ttbr_addr>]",
        "  This command displays process page table mapping information.",
        "\n",
        "OPTIONS",
        "  -a",
        "    Display overview of all process page tables in the system.",
        "    Shows PID, command name, page table address, and basic statistics.",
        "",
        "  -p <pid>",
        "    Display detailed page table mappings for the specified process.",
        "    Shows virtual-to-physical address mappings with attributes.",
        "",
        "  -t <ttbr_addr>",
        "    Display page table mappings for the specified TTBR address (in hex).",
        "    Directly analyzes page table at the given physical address.",
        "\n",
        "EXAMPLES",
        "  Display overview of all process page tables:",
        "    %s> pagetable -a",
        "    Process Page Tables Overview",
        "    ┌─────┬─────────────────┬──────────────────┬──────────────────┬────────┐",
        "    │ PID │ Command         │ mm_struct        │ PGD (Physical)   │ Levels │",
        "    ├─────┼─────────────────┼──────────────────┼──────────────────┼────────┤",
        "    │   1 │ systemd         │ 0xffffff8012345678│ 0x0000000012345000│    4   │",
        "    │ 1234│ myprocess       │ 0xffffff8012346789│ 0x0000000012346000│    4   │",
        "    └─────┴─────────────────┴──────────────────┴──────────────────┴────────┘",
        "\n",
        "  Display detailed page table for specific process:",
        "    %s> pagetable -p 1234",
        "    Process: PID=1234, COMM=myprocess",
        "    Task memory info:",
        "      mm_struct    : 0xffffff8012345678",
        "      pgd (virt)   : 0xffffff8012345000",
        "      pgd (phys)   : 0x12345000",
        "      levels       : 4",
        "",
        "    Client: myprocess (PID:1234)",
        "    TTBR0: 0x12345000",
        "    Levels: 4",
        "    Type: Process Page Table",
        "    [VA Start -- VA End  ] [Size      ] [PA Start   -- PA End  ] [Attributes][Page Table Entry Size] [Memory Type] [Shareability] [Non-Executable]",
        "    0x0000000000400000--0x0000000000401fff [0x2000     ] A:0x0000000080400000--0x0000000080401fff [0x2000     ] [R/W][4K] [Cached] [Inner-Shareable] [False]",
        "\n",
        "  Display page table for specific TTBR address:",
        "    %s> pagetable -t 12345000",
        "    TTBR Page Table Analysis",
        "    TTBR Address: 0x12345000",
        "",
        "    Client: TTBR:0x12345000",
        "    TTBR0: 0x12345000",
        "    Levels: 4",
        "    Type: Process Page Table",
        "    [VA Start -- VA End  ] [Size      ] [PA Start   -- PA End  ] [Attributes][Page Table Entry Size] [Memory Type] [Shareability] [Non-Executable]",
        "    0x0000000000400000--0x0000000000401fff [0x2000     ] A:0x0000000080400000--0x0000000080401fff [0x2000     ] [R/W][4K] [Cached] [Inner-Shareable] [False]",
        "\n",
    };
}

/**
 * @brief Default constructor
 */
PageTable::PageTable() {

}

/**
 * @brief Parse and collect process page table information
 *
 * Iterates through all processes in the system and extracts page table
 * information including PGD address, levels, and validity status.
 */
void PageTable::parse_process_pagetables() {
    process_list.clear();

    // Iterate through all tasks
    for (auto& task_addr : for_each_process()) {
        struct task_context *tc = task_to_context(task_addr);
        if (!tc || tc->pid <= 0) {
            continue;
        }

        std::shared_ptr<process_pagetable> pt_info = std::make_shared<process_pagetable>();
        pt_info->pid = tc->pid;
        pt_info->comm = std::string(tc->comm);
        pt_info->mm_struct = tc->mm_struct;
        pt_info->valid = false;

        // Check if process has valid mm_struct
        if (is_valid_process_mm(tc->mm_struct)) {
            // Read PGD from mm_struct
            pt_info->pgd_virt = read_pointer(tc->mm_struct + field_offset(mm_struct, pgd), "pgd");

            if (is_kvaddr(pt_info->pgd_virt)) {
                // Convert virtual PGD address to physical
                pt_info->pgd_phys = virt_to_phys_pgd(pt_info->pgd_virt);
                pt_info->levels = detect_pagetable_levels();
                pt_info->valid = true;
            }
        }

        process_list.push_back(pt_info);
    }

    LOGD("Parsed %zu process page tables\n", process_list.size());
}

/**
 * @brief Get page table information for specific PID
 *
 * @param pid Process ID to look up
 * @return Shared pointer to process page table info, or nullptr if not found
 */
std::shared_ptr<process_pagetable> PageTable::get_process_pagetable(int pid) {
    // Parse if not already done
    if (process_list.empty()) {
        parse_process_pagetables();
    }
    // Find the process
    for (const auto& pt : process_list) {
        if (pt->pid == pid) {
            return pt;
        }
    }
    return nullptr;
}

/**
 * @brief Print detailed page table for specific process
 *
 * @param pid Process ID to display page table for
 */
void PageTable::print_process_pagetable(int pid) {
    std::shared_ptr<process_pagetable> pt_info = get_process_pagetable(pid);

    if (!pt_info) {
        PRINT("Process with PID %d not found\n", pid);
        return;
    }

    if (!pt_info->valid) {
        PRINT("Process PID=%d (%s) has invalid or no page table\n",
              pt_info->pid, pt_info->comm.c_str());
        return;
    }

    // Print process information
    PRINT("Process: PID=%d, COMM=%s\n", pt_info->pid, pt_info->comm.c_str());
    PRINT("Task memory info:\n");
    PRINT("  mm_struct    : 0x%lx\n", pt_info->mm_struct);
    PRINT("  pgd (virt)   : 0x%lx\n", pt_info->pgd_virt);
    PRINT("  pgd (phys)   : 0x%lx\n", pt_info->pgd_phys);
    PRINT("  levels       : %u\n", pt_info->levels);

    // Display architecture information
    if (is_arm64_architecture()) {
        PRINT("  architecture : ARM64\n");
    } else if (is_arm32_architecture()) {
        PRINT("  architecture : ARM32");
        if (is_lpae_enabled()) {
            PRINT(" (LPAE enabled)\n");
        } else {
            PRINT(" (LPAE disabled)\n");
        }
    } else {
        PRINT("  architecture : Unknown\n");
    }
    PRINT("\n");

    // Use appropriate parser based on architecture detection
    std::string client_name = pt_info->comm + " (PID:" + std::to_string(pt_info->pid) + ")";
    parse_and_print_pagetable(pt_info->pgd_phys, pt_info->levels, client_name);
}

/**
 * @brief Print overview of all process page tables
 */
void PageTable::print_all_process_pagetables() {
    // Parse if not already done
    if (process_list.empty()) {
        parse_process_pagetables();
    }

    if (process_list.empty()) {
        PRINT("No processes found\n");
        return;
    }

    // Count valid page tables
    size_t valid_count = 0;
    for (const auto& pt : process_list) {
        if (pt->valid) {
            valid_count++;
        }
    }

    PRINT("Process Page Tables Overview (%zu total, %zu valid)\n",
          process_list.size(), valid_count);
    PRINT("┌───────┬────────────────────┬───────────────────┬───────────────────┬────────┐\n");
    PRINT("│  PID  │ Command            │ mm_struct         │ PGD (Physical)    │ Levels │\n");
    PRINT("├───────┼────────────────────┼───────────────────┼───────────────────┼────────┤\n");

    // Sort by PID for consistent output
    std::vector<std::shared_ptr<process_pagetable>> sorted_list = process_list;
    std::sort(sorted_list.begin(), sorted_list.end(),
              [](const std::shared_ptr<process_pagetable>& a, const std::shared_ptr<process_pagetable>& b) {
                  return a->pid < b->pid;
              });

    // Display only valid page tables
    for (const auto& pt : sorted_list) {
        if (pt->valid) {
            PRINT("│%6d │%-19s │0x%016lx │0x%016lx │   %u    │\n",
                  pt->pid, pt->comm.c_str(), pt->mm_struct, pt->pgd_phys, pt->levels);
        }
    }

    PRINT("└───────┴────────────────────┴───────────────────┴───────────────────┴────────┘\n");
}

/**
 * @brief Check if mm_struct is valid
 *
 * @param mm_struct Address of mm_struct to check
 * @return true if valid, false otherwise
 */
bool PageTable::is_valid_process_mm(ulong mm_struct) {
    if (!is_kvaddr(mm_struct)) {
        return false;
    }

    // Check if mm_users and mm_count are reasonable
    int mm_users = read_int(mm_struct + field_offset(mm_struct, mm_users), "mm_users");
    int mm_count = read_int(mm_struct + field_offset(mm_struct, mm_count), "mm_count");

    return (mm_users > 0 && mm_count > 0);
}

/**
 * @brief Detect page table levels from kernel configuration
 *
 * @return Number of page table levels (3 or 4)
 */
uint PageTable::detect_pagetable_levels() {
    // Try to detect from kernel configuration
    std::string va_bits = get_config_val("CONFIG_ARM64_VA_BITS");
    if (!va_bits.empty()) {
        int bits = std::stoi(va_bits);
        if (bits <= 39) {
            return 3;  // 3-level page tables for <= 39-bit VA
        } else {
            return 4;  // 4-level page tables for > 39-bit VA
        }
    }

    // Default to 4 levels if can't determine
    return 4;
}

/**
 * @brief Convert virtual PGD address to physical
 *
 * @param virt_addr Virtual address of PGD
 * @return Physical address of PGD
 */
ulong PageTable::virt_to_phys_pgd(ulong virt_addr) {
    if (!is_kvaddr(virt_addr)) {
        return 0;
    }

    // Use kernel's virt_to_phys conversion
    return virt_to_phy(virt_addr);
}

/**
 * @brief Check if running on ARM64 architecture
 *
 * @return true if ARM64, false otherwise
 */
bool PageTable::is_arm64_architecture() {
    // Check for ARM64 specific configuration options
    std::string arch = get_config_val("CONFIG_ARM64");
    if (arch == "y") {
        return true;
    }
    // Check machine type from crash utility
    if (machine_type(TO_CONST_STRING("ARM64"))) {
        return true;
    }
    return false;
}

/**
 * @brief Check if running on ARM32 architecture
 *
 * @return true if ARM32, false otherwise
 */
bool PageTable::is_arm32_architecture() {
    // Check for ARM32 specific configuration options
    std::string arch = get_config_val("CONFIG_ARM");
    if (arch == "y") {
        return true;
    }
    // Check machine type from crash utility
    if (machine_type(TO_CONST_STRING("ARM"))) {
        return true;
    }

    return false;
}

/**
 * @brief Check if LPAE (Large Physical Address Extension) is enabled on ARM32
 *
 * @return true if LPAE is enabled, false otherwise
 */
bool PageTable::is_lpae_enabled() {
    // Only relevant for ARM32
    if (!is_arm32_architecture()) {
        return false;
    }

    // Check for LPAE configuration option
    std::string lpae = get_config_val("CONFIG_ARM_LPAE");
    if (lpae == "y") {
        return true;
    }
    return false;
}

/**
 * @brief Parse page table with appropriate parser based on architecture
 *
 * @param pgd_phys Physical address of page global directory
 * @param levels Number of page table levels
 * @param client_name Name of the client for display
 */
void PageTable::parse_and_print_pagetable(ulong pgd_phys, uint levels, const std::string& client_name) {
#if defined(ARM64)
    if (is_arm64_architecture()) {
        // Use ARM64 page table parser
        LOGD("Using ARM64 page table parser for %s\n", client_name.c_str());
        AArch64PTParser parser;
        parser.parse_and_print_tables(pgd_phys, levels, client_name, PROCESS_PAGE_TABLE);
    }
#else
    if (is_arm32_architecture() && is_lpae_enabled()) {
        // Use ARM32 LPAE page table parser
        LOGD("Using ARM32 LPAE page table parser for %s\n", client_name.c_str());
        // Create LPAE parser and use it
        try {
            // Create MMU instance with default constructor
            // All parameters will be set in parse_long_form_tables
            Armv7LPAEMMU parser;
            bool success = parser.parse_long_form_tables(
                pgd_phys, client_name, true);  // true = is_process_table

            if (!success) {
                PRINT("Failed to parse ARM32 LPAE page table for %s\n", client_name.c_str());
            }
        } catch (const std::exception& e) {
            PRINT("Error parsing ARM32 LPAE page table for %s: %s\n", client_name.c_str(), e.what());
        }
    } else {
        // Unknown architecture
        PRINT("Unknown architecture - cannot determine page table format\n");
        PRINT("Client: %s\n", client_name.c_str());
        PRINT("PGD Physical Address: 0x%lx\n", pgd_phys);
        PRINT("Levels: %u\n", levels);
    }
#endif
}

/**
 * @brief Print page table for specified TTBR address
 *
 * @param ttbr_addr Physical address of TTBR (Translation Table Base Register)
 */
void PageTable::print_ttbr_pagetable(ulong ttbr_addr) {
    if (ttbr_addr == 0) {
        PRINT("Error: Invalid TTBR address (0x0)\n");
        return;
    }

    PRINT("TTBR Page Table Analysis\n");
    PRINT("TTBR Address: 0x%lx\n", ttbr_addr);

    // Detect architecture and page table format
    if (is_arm64_architecture()) {
        PRINT("Architecture: ARM64\n");
    } else if (is_arm32_architecture()) {
        PRINT("Architecture: ARM32");
        if (is_lpae_enabled()) {
            PRINT(" (LPAE enabled)\n");
        } else {
            PRINT(" (LPAE disabled)\n");
        }
    } else {
        PRINT("Architecture: Unknown\n");
    }
    PRINT("\n");

    // Detect page table levels
    uint levels = detect_pagetable_levels();

    // Use appropriate parser
    std::string client_name = "TTBR:0x" + std::to_string(ttbr_addr);
    parse_and_print_pagetable(ttbr_addr, levels, client_name);
}

#pragma GCC diagnostic pop
