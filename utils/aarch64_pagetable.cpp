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

#include "aarch64_pagetable.h"
#include <algorithm>
#include <vector>

/**
 * Main command execution
 */
void AArch64PTParser::cmd_main(void) {

}

/**
 * Initialize command metadata
 */
void AArch64PTParser::init_command(void) {

}

void AArch64PTParser::init_offset(void) {

}

/**
 * Read 64-bit value from physical or virtual address based on page table type
 */
uint64_t AArch64PTParser::read_pte_entry(ulong addr, const char* desc) {
    uint64_t value = 0;

    if (current_page_table_type == PROCESS_PAGE_TABLE) {
        // For process page tables, read directly from physical address
        if (!readmem(addr, PHYSADDR, &value, sizeof(value), (char*)desc, RETURN_ON_ERROR)) {
            LOGD("Failed to read %s from physical address 0x%lx\n", desc, addr);
            return 0;
        }
    } else {
        // For IOMMU page tables, use phy_to_virt conversion
        ulong virt_addr = phy_to_virt(addr);
        if (!is_kvaddr(virt_addr)) {
            LOGD("Failed to convert physical address 0x%lx to virtual for %s\n", addr, desc);
            return 0;
        }
        value = read_ulonglong(virt_addr, desc);
    }

    return value;
}

/**
 * Get page size order string
 */
std::string AArch64PTParser::get_order_string(uint64_t size) {
    if (size == SZ_4K) return "4K";
    if (size == SZ_64K) return "64K";
    if (size == SZ_2M) return "2M";
    if (size == SZ_32M) return "32M";
    if (size == SZ_1G) return "1G";
    if (size == SZ_256G) return "256G";
    return "UNKNOWN";
}

/**
 * Add a collapsed mapping representing FlatMappings between first and last
 */
void AArch64PTParser::add_collapsed_mapping(std::map<uint64_t, CollapsedMapping>& mappings,
                                           const FlatMapping& first, const FlatMapping& last) {
    uint64_t virt_start = first.virt;

    CollapsedMapping map(
        virt_start,
        last.virt + last.map_size,
        first.phys,
        (last.phys & 0xFFFFFFFFF000ULL) + last.map_size,
        first.type,
        first.map_size,
        first.attr_indx_str,
        first.shareability_str,
        first.execute_never_str,
        first.mapped
    );

    if (mappings.find(virt_start) == mappings.end()) {
        mappings.insert({virt_start, map});
    } else {
        mappings.erase(virt_start);
        map.map_type = "Duplicate";
        mappings.insert({virt_start, map});
    }
}

/**
 * Combine adjacent holes in the page table, but leave all valid entries unchanged
 */
std::map<uint64_t, CollapsedMapping> AArch64PTParser::create_collapsed_mapping(
    const std::map<uint64_t, FlatMapping>& flat_mapping) {

    std::map<uint64_t, CollapsedMapping> collapsed_mapping;

    if (flat_mapping.empty()) {
        return collapsed_mapping;
    }

    // Get sorted virtual addresses
    std::vector<uint64_t> virt_addrs;
    for (const auto& pair : flat_mapping) {
        virt_addrs.push_back(pair.first);
    }
    std::sort(virt_addrs.begin(), virt_addrs.end());

    FlatMapping start_map = flat_mapping.at(virt_addrs[0]);
    FlatMapping prev_map = start_map;
    bool new_mapping = false;

    for (size_t i = 1; i < virt_addrs.size(); ++i) {
        const FlatMapping& map = flat_mapping.at(virt_addrs[i]);

        if (map.map_size == prev_map.map_size &&
            map.type == prev_map.type &&
            map.mapped == prev_map.mapped &&
            map.attr_indx_str == prev_map.attr_indx_str &&
            !map.mapped) {
            new_mapping = false;
        } else {
            new_mapping = true;
        }

        if (new_mapping) {
            add_collapsed_mapping(collapsed_mapping, start_map, prev_map);
            start_map = map;
        }

        prev_map = map;
    }

    // Add the last entry
    add_collapsed_mapping(collapsed_mapping, start_map, prev_map);
    return collapsed_mapping;
}

/**
 * Internal helper to add a flat mapping
 */
void AArch64PTParser::add_flat_mapping_internal(std::map<uint64_t, FlatMapping>& mappings,
                                               uint64_t virt, int64_t phy_addr,
                                               const std::string& map_type_str, uint64_t page_size,
                                               const std::string& attr_indx_str,
                                               const std::string& shareability_str,
                                               const std::string& execute_never_str, bool mapped) {
    FlatMapping map(virt, phy_addr, map_type_str, page_size, attr_indx_str,
                   shareability_str, execute_never_str, mapped);

    if (mappings.find(virt) == mappings.end()) {
        mappings.insert({virt, map});
    } else {
        mappings.erase(virt);
        map.type = "Duplicate";
        mappings.insert({virt, map});
    }
}

/**
 * Add a flat mapping with attribute parsing
 */
void AArch64PTParser::add_flat_mapping(std::map<uint64_t, FlatMapping>& mappings,
                                      int fl_idx, int sl_idx, int tl_idx, int ll_idx,
                                      int64_t phy_addr, uint32_t map_type, uint64_t page_size,
                                      int attr_indx, int shareability, int xn_bit, bool mapped) {
    // Calculate virtual address from indices
    uint64_t virt = ((uint64_t)fl_idx << 39) | ((uint64_t)sl_idx << 30) |
                    ((uint64_t)tl_idx << 21) | ((uint64_t)ll_idx << 12);

    // Parse map type
    std::string map_type_str = "[R/W]";
    if (map_type == LL_AP_RO) {
        map_type_str = "[RO]";
    } else if (map_type == LL_AP_PR_RW) {
        map_type_str = "[P R/W]";
    } else if (map_type == LL_AP_PR_RO) {
        map_type_str = "[P RO]";
    }

    // Parse shareability
    std::string shareability_str = "N/A";
    if (shareability != -1) {
        if (shareability == SH_NON_SHARE) {
            shareability_str = "Non-Shareable";
        } else if (shareability == SH_RESERVED) {
            shareability_str = "Reserved";
        } else if (shareability == SH_OUTER_SHARE) {
            shareability_str = "Outer-Shareable";
        } else if (shareability == SH_INNER_SHARE) {
            shareability_str = "Inner-Shareable";
        }
    }

    // Parse attribute index
    std::string attr_indx_str = "N/A";
    if (attr_indx != -1) {
        if (attr_indx == ATTR_IDX_NONCACHED) {
            attr_indx_str = "Non-Cached";
        } else if (attr_indx == ATTR_IDX_CACHE) {
            attr_indx_str = "Cached";
        } else if (attr_indx == ATTR_IDX_DEV) {
            attr_indx_str = "Device";
        } else if (attr_indx == ATTR_IDX_UPST) {
            attr_indx_str = "UPSTREAM";
        } else if (attr_indx == ATTR_IDX_LLC_NWA) {
            attr_indx_str = "LLC_NWA";
        }
    }

    // Parse execute never bit
    std::string execute_never_str;
    if (xn_bit == 1) {
        execute_never_str = "True";
    } else if (xn_bit == 0) {
        execute_never_str = "False";
    } else {
        execute_never_str = "N/A";
    }

    // Add the mapping
    add_flat_mapping_internal(mappings, virt, phy_addr, map_type_str, page_size,
                              attr_indx_str, shareability_str, execute_never_str, mapped);
}

/**
 * Get super section (1GB block) mapping information
 */
MappingInfo AArch64PTParser::get_super_section_mapping_info(ulong pg_table, int index) {
    MappingInfo info = {-1, SZ_1G, 0, true, 0, -1, -1, -1};

    uint64_t phy_addr = read_pte_entry(pg_table, "super_section_entry");

    if (phy_addr != 0) {
        info.map_type = phy_addr & LL_AP_BITS;
        info.phy_addr = phy_addr & 0xFFFFC0000FFFULL;
    } else {
        info.status = false;
    }

    return info;
}

/**
 * Get section (2MB/32MB block) mapping information
 */
MappingInfo AArch64PTParser::get_section_mapping_info(ulong pg_table, int index) {
    MappingInfo info = {-1, SZ_2M, 0, true, 0, 0, -1, 0};

    uint64_t phy_addr = read_pte_entry(pg_table, "section_entry");

    if (phy_addr != 0) {
        info.map_type = phy_addr & LL_AP_BITS;
        info.attr_indx = (phy_addr & LL_ATTR_INDX) >> 2;

        if (info.attr_indx == ATTR_IDX_NONCACHED || info.attr_indx == ATTR_IDX_CACHE) {
            info.shareability = phy_addr & LL_SH_BITS;
        }

        if (phy_addr & LL_XN) {
            info.xn_bit = 1;
        }

        if (phy_addr & LL_CH) {
            info.phy_addr = phy_addr & 0xFFFFFE000FFFULL;
            info.page_size = SZ_32M;
            info.skip_count = 15;  // Current + next 15 entries are contiguous
        } else {
            info.phy_addr = phy_addr & 0xFFFFFFE00FFFULL;
            info.page_size = SZ_2M;
        }
    } else {
        info.status = false;
    }

    return info;
}

/**
 * Get page (4KB/64KB) mapping information
 */
MappingInfo AArch64PTParser::get_mapping_info(ulong pg_table, int index) {
    MappingInfo info = {-1, SZ_4K, 0, true, 0, 0, -1, 0};

    ulong ll_pte = pg_table + (index * 8);
    uint64_t phy_addr = read_pte_entry(ll_pte, "page_entry");

    if (phy_addr != 0) {
        info.map_type = phy_addr & LL_AP_BITS;

        if (phy_addr & LL_TYPE_PAGE) {
            info.phy_addr = phy_addr & 0xFFFFFFFFF000ULL;
            info.attr_indx = (phy_addr & LL_ATTR_INDX) >> 2;

            if (info.attr_indx == ATTR_IDX_NONCACHED || info.attr_indx == ATTR_IDX_CACHE) {
                info.shareability = phy_addr & LL_SH_BITS;
            }

            if (phy_addr & LL_XN) {
                info.xn_bit = 1;
            }

            if (phy_addr & LL_CH) {
                info.phy_addr = phy_addr & 0xFFFFFFFF0FFFULL;
                info.page_size = SZ_64K;
                info.skip_count = 15;  // Current + next 15 entries are contiguous
            }
        } else {
            // Error condition if at last level it is not LL_TYPE_PAGE
            info.phy_addr = phy_addr;
            info.status = false;
        }
    }

    return info;
}

/**
 * Read first level page table entry
 */
std::pair<uint64_t, ulong> AArch64PTParser::fl_entry(ulong fl_pte, int skip_fl) {
    uint64_t fl_pg_table_entry = read_pte_entry(fl_pte, "fl_pg_table_entry");
    ulong sl_pte = fl_pg_table_entry & FLSL_BASE_MASK;

    if (skip_fl == 1) {
        // Make 1st level entry look like dummy entry of type table
        // for 3-level page tables
        fl_pg_table_entry = FLSL_TYPE_TABLE;
        sl_pte = fl_pte;
    }

    return {fl_pg_table_entry, sl_pte};
}

/**
 * Parse 2nd level page table (3rd and 4th level entries)
 */
std::map<uint64_t, FlatMapping> AArch64PTParser::parse_2nd_level_table(
    uint64_t sl_pg_table_entry, int fl_index, int sl_index,
    std::map<uint64_t, FlatMapping> tmp_mapping) {

    ulong tl_pte = sl_pg_table_entry & FLSL_BASE_MASK;
    int section_skip_count = 0;

    for (int tl_index = 0; tl_index < NUM_TL_PTE; ++tl_index) {
        uint64_t tl_pg_table_entry = read_pte_entry(tl_pte, "tl_pg_table_entry");

        if (tl_pg_table_entry == 0) {
            add_flat_mapping(tmp_mapping, fl_index, sl_index, tl_index, 0,
                           -1, -1, SZ_2M, -1, -1, -1, false);
            tl_pte += 8;
            continue;
        }

        uint32_t tl_entry_type = tl_pg_table_entry & FLSL_PTE_TYPE_MASK;

        if (tl_entry_type == FLSL_TYPE_TABLE) {
            ulong ll_pte = tl_pg_table_entry & FLSL_BASE_MASK;
            int skip_count = 0;

            for (int ll_index = 0; ll_index < NUM_LL_PTE; ++ll_index) {
                if (skip_count > 0) {
                    skip_count--;
                    continue;
                }

                MappingInfo info = get_mapping_info(ll_pte, ll_index);

                if (info.status && info.phy_addr != -1) {
                    add_flat_mapping(tmp_mapping, fl_index, sl_index, tl_index, ll_index,
                                   info.phy_addr, info.map_type, info.page_size,
                                   info.attr_indx, info.shareability, info.xn_bit, true);
                } else {
                    add_flat_mapping(tmp_mapping, fl_index, sl_index, tl_index, ll_index,
                                   -1, -1, info.page_size, info.attr_indx,
                                   info.shareability, info.xn_bit, false);
                }

                skip_count = info.skip_count;
            }
        } else if (tl_entry_type == FLSL_TYPE_BLOCK) {
            if (section_skip_count > 0) {
                section_skip_count--;
                tl_pte += 8;
                continue;
            }

            MappingInfo info = get_section_mapping_info(tl_pte, tl_index);

            if (info.status && info.phy_addr != -1) {
                add_flat_mapping(tmp_mapping, fl_index, sl_index, tl_index, 0,
                               info.phy_addr, info.map_type, info.page_size,
                               info.attr_indx, info.shareability, info.xn_bit, true);
            }

            section_skip_count = info.skip_count;
        }

        tl_pte += 8;
    }

    return tmp_mapping;
}

/**
 * Create flat mappings from page table
 */
std::map<uint64_t, FlatMapping> AArch64PTParser::create_flat_mappings(ulong pg_table, int level) {
    std::map<uint64_t, FlatMapping> tmp_mapping;

    ulong fl_pte = pg_table;
    int skip_fl = 0;
    int fl_range = NUM_FL_PTE;

    if (level == 3) {
        skip_fl = 1;
        fl_range = 1;
    }

    for (int fl_index = 0; fl_index < fl_range; ++fl_index) {
        std::pair<uint64_t, ulong> fl_result = fl_entry(fl_pte, skip_fl);
        uint64_t fl_pg_table_entry = fl_result.first;
        ulong sl_pte = fl_result.second;

        if (fl_pg_table_entry == 0) {
            add_flat_mapping(tmp_mapping, fl_index, 0, 0, 0,
                           -1, -1, SZ_256G, -1, -1, -1, false);
            fl_pte += 8;
            continue;
        }

        for (int sl_index = 0; sl_index < NUM_SL_PTE; ++sl_index) {
            uint64_t sl_pg_table_entry;
            if (skip_fl == 0) {
                sl_pg_table_entry = read_pte_entry(sl_pte, "sl_pg_table_entry");
            } else {
                sl_pg_table_entry = read_pte_entry(sl_pte, "sl_pg_table_entry");
            }

            if (sl_pg_table_entry == 0) {
                add_flat_mapping(tmp_mapping, fl_index, sl_index, 0, 0,
                               -1, -1, SZ_1G, -1, -1, -1, false);
                sl_pte += 8;
                continue;
            }

            uint32_t sl_entry_type = sl_pg_table_entry & FLSL_PTE_TYPE_MASK;

            if (sl_entry_type == FLSL_TYPE_TABLE) {
                tmp_mapping = parse_2nd_level_table(sl_pg_table_entry, fl_index,
                                                   sl_index, tmp_mapping);
            } else if (sl_entry_type == FLSL_TYPE_BLOCK) {
                MappingInfo info = get_super_section_mapping_info(sl_pte, sl_index);

                if (info.status && info.phy_addr != -1) {
                    // TODO: Fix memory attributes for 2nd-level entry
                    add_flat_mapping(tmp_mapping, fl_index, sl_index, 0, 0,
                                   info.phy_addr, info.map_type, info.page_size,
                                   -1, -1, -1, true);
                }
            }

            sl_pte += 8;
        }

        fl_pte += 8;
    }

    return tmp_mapping;
}

/**
 * Parse and print AArch64 page tables
 */
void AArch64PTParser::parse_and_print_tables(ulong pg_table, uint level, const std::string& client_name, PageTableType type) {
    PRINT("Client: %s\n", client_name.c_str());
    PRINT("TTBR0: 0x%lx\n", pg_table);
    PRINT("Levels: %u\n", level);
    PRINT("Type: %s\n", (type == PROCESS_PAGE_TABLE) ? "Process Page Table" : "IOMMU Page Table");

    PRINT("%-34s %-12s %-34s %-11s%-6s %-13s %-17s %s\n",
          "[VA Start -- VA End  ]", "[Size      ]", "[PA Start   -- PA End  ]",
          "[Attributes]", "[Size]", "[Memory Type]", "[Shareability]", "[Non-Executable]");

    if (pg_table == 0) {
        PRINT("No Page Table Found. (Probably a secure domain)\n");
        return;
    }

    // Add debug output for page table parsing
    LOGD("Starting page table parsing: pg_table=0x%lx, level=%u, type=%s\n",
         pg_table, level, (type == PROCESS_PAGE_TABLE) ? "PROCESS" : "IOMMU");

    // Store page table type for use in helper functions
    current_page_table_type = type;

    // Test address accessibility based on page table type
    if (type == IOMMU_PAGE_TABLE) {
        // For IOMMU page tables, use phy_to_virt conversion
        ulong pg_table_virt = phy_to_virt(pg_table);
        LOGD("IOMMU: phy_to_virt(0x%lx) = 0x%lx, is_kvaddr=%s\n",
             pg_table, pg_table_virt, is_kvaddr(pg_table_virt) ? "true" : "false");

        if (!is_kvaddr(pg_table_virt)) {
            PRINT("ERROR: Cannot convert IOMMU page table physical address 0x%lx to virtual address\n", pg_table);
            return;
        }
    } else {
        // For process page tables, try direct physical memory access
        LOGD("PROCESS: Using direct physical memory access for 0x%lx\n", pg_table);

        // Test if we can read from the physical address directly
        uint64_t test_entry = 0;
        if (!readmem(pg_table, PHYSADDR, &test_entry, sizeof(test_entry), (char*)"test_entry", RETURN_ON_ERROR)) {
            PRINT("ERROR: Cannot read from process page table physical address 0x%lx\n", pg_table);
            PRINT("This might indicate the page table is not accessible or corrupted\n");
            return;
        }
        LOGD("PROCESS: Successfully read test entry 0x%lx from physical address\n", test_entry);
    }

    std::map<uint64_t, FlatMapping> flat_mapping = create_flat_mappings(pg_table, level);
    LOGD("Created %zu flat mappings\n", flat_mapping.size());

    if (flat_mapping.empty()) {
        PRINT("No page table entries found. Possible causes:\n");
        PRINT("  1. Page table is empty (process has no mappings)\n");
        PRINT("  2. Address translation failed\n");
        PRINT("  3. Page table level detection is incorrect\n");
        PRINT("  4. Physical memory access failed\n");
        return;
    }

    std::map<uint64_t, CollapsedMapping> collapsed_mapping = create_collapsed_mapping(flat_mapping);
    LOGD("Created %zu collapsed mappings\n", collapsed_mapping.size());

    for (const auto& pair : collapsed_mapping) {
        const CollapsedMapping& mapping = pair.second;

        char va_range[64], size_str[32], pa_range[64];
        char attr_str[16], size_tag[16], mem_type[32], share_str[32], exec_str[16];

        if (mapping.mapped) {
            snprintf(va_range, sizeof(va_range), "0x%016lx--0x%016lx", mapping.virt_start, mapping.virt_end);
            snprintf(size_str, sizeof(size_str), "[0x%-10lx]", mapping.map_size);
            snprintf(pa_range, sizeof(pa_range), "A:0x%016lx--0x%016lx", mapping.phys_start, mapping.phys_end);
            snprintf(attr_str, sizeof(attr_str), "%s", mapping.map_type.c_str());
            snprintf(size_tag, sizeof(size_tag), "[%-4s]", get_order_string(mapping.map_size).c_str());
            snprintf(mem_type, sizeof(mem_type), "[%s]", mapping.attr_indx_str.c_str());
            snprintf(share_str, sizeof(share_str), "[%s]", mapping.shareability_str.c_str());
            snprintf(exec_str, sizeof(exec_str), "[%s]", mapping.execute_never_str.c_str());

            PRINT("%-34s %-12s %-34s %-11s%-6s %-13s %-17s %s\n",
                    va_range, size_str, pa_range, attr_str, size_tag, mem_type, share_str, exec_str);
        } else {
            snprintf(va_range, sizeof(va_range), "0x%016lx--0x%016lx", mapping.virt_start, mapping.virt_end);
            snprintf(size_str, sizeof(size_str), "[0x%-10lx]", mapping.virt_end - mapping.virt_start + 1);

            PRINT("%-34s %-12s [UNMAPPED]\n", va_range, size_str);
        }
    }
}
