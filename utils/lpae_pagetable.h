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

#ifndef LPAE_PAGETABLE_H_
#define LPAE_PAGETABLE_H_

#include "../plugin.h"
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>

// Constants for page table structure (ARM32 LPAE specific)
constexpr size_t LPAE_NUM_FL_PTE = 4;      // First-level page table entries
constexpr size_t LPAE_NUM_SL_PTE = 512;    // Second-level page table entries
constexpr size_t LPAE_NUM_TL_PTE = 512;    // Third-level page table entries

// Page sizes (ARM32 LPAE specific)
constexpr uint64_t LPAE_SZ_4K = 0x1000;
constexpr uint64_t LPAE_SZ_2M = 0x200000;
constexpr uint64_t LPAE_SZ_1G = 0x40000000;

// Descriptor types
enum class DescriptorType : uint8_t {
    INVALID = 0x0,
    BLOCK = 0x1,
    TABLE = 0x3,
    TL_RESERVED = 0x1,
    TL_PAGE = 0x3
};

// Memory attributes structure
struct MemoryAttributes {
    uint8_t software;           // Software bits [58:55]
    bool XN;                    // Execute Never [54]
    bool PXN;                   // Privileged Execute Never [53]
    bool contiguous_hint;       // Contiguous hint [52]
    bool nG;                    // Not Global [11]
    bool AF;                    // Access Flag [10]
    uint8_t sh_10;             // Shareability [9:8]
    uint8_t ap_21;             // Access Permissions [7:6]
    bool ns;                    // Non-Secure [5]
    uint8_t attr_index_20;     // Attribute Index [4:2]

    MemoryAttributes();
    std::vector<std::string> get_attribute_strings() const;
    bool operator==(const MemoryAttributes& other) const noexcept;
};

// Mapping information base class (LPAE specific)
class LPAEMappingInfo {
public:
    virtual ~LPAEMappingInfo() = default;
    virtual bool is_leaf() const = 0;
};

// Leaf mapping (actual memory mapping)
class LPAELeafMapping : public LPAEMappingInfo {
public:
    uint64_t virt_addr;
    uint64_t phys_addr;
    uint64_t page_size;
    MemoryAttributes attributes;

    LPAELeafMapping(uint64_t virt, uint64_t phys, uint64_t size,
                    const MemoryAttributes& attrs);

    bool is_leaf() const override { return true; }
    std::pair<uint64_t, uint64_t> phys_addr_range() const noexcept;
    std::string to_string() const;
};

// Table mapping (pointer to next level)
class LPAETableMapping : public LPAEMappingInfo {
public:
    uint64_t next_table_addr;

    explicit LPAETableMapping(uint64_t addr);
    bool is_leaf() const override { return false; }
    std::string to_string() const;
};

// Mapping range type: (virt_start, virt_end) -> LPAELeafMapping or nullptr (unmapped)
using LPAEMappingRange = std::pair<uint64_t, uint64_t>;
using LPAEMappingMap = std::map<LPAEMappingRange, std::shared_ptr<LPAELeafMapping>>;

// Virtual address register for index extraction
class VirtualAddressRegister {
public:
    uint64_t value;
    uint32_t input_addr_split;

    VirtualAddressRegister(uint64_t addr, uint32_t split);

    uint32_t get_fl_index() const noexcept;
    uint32_t get_sl_index() const noexcept;
    uint32_t get_tl_index() const noexcept;
    uint32_t get_page_offset() const noexcept;
    uint64_t get_rest(uint32_t n) const noexcept;
};

// ARMv7 LPAE MMU implementation
class Armv7LPAEMMU : public ParserPlugin {
public:
    Armv7LPAEMMU();

    // ParserPlugin interface implementation
    void cmd_main(void) override;
    void init_command(void) override;
    void init_offset(void) override;

    // Main translation function
    std::unique_ptr<LPAEMappingInfo> translate(uint64_t virt_addr);

    // Level-specific translation functions
    std::unique_ptr<LPAEMappingInfo> translate_first_level(VirtualAddressRegister& virt_r);
    std::unique_ptr<LPAEMappingInfo> translate_second_level(VirtualAddressRegister& virt_r,
                                                             uint64_t level2_table_addr,
                                                             uint32_t block_split = 0);
    std::unique_ptr<LPAEMappingInfo> translate_third_level(VirtualAddressRegister& virt_r,
                                                            uint64_t level3_table_addr);

    uint32_t get_input_addr_split() const { return input_addr_split_; }

    // High-level page table analysis functions (merged from LPAEIommuLib)
    LPAEMappingMap get_flat_mappings();
    LPAEMappingMap get_coalesced_mappings(const LPAEMappingMap& flat_mappings);
    void print_lpae_mappings(const LPAEMappingMap& mappings, std::ostream& outfile) const;
    void print_lpae_mappings_direct(const LPAEMappingMap& mappings) const;

    // Main entry point for page table parsing and printing
    // @param pg_table: Physical address of the page table base
    // @param client_name: Name of the client for display purposes
    // @param is_process_table: true for process page tables, false for IOMMU page tables
    // Note: Only supports 4GB (32-bit) virtual address space (T0SZ=0)
    bool parse_long_form_tables(uint64_t pg_table,
                                const std::string& client_name,
                                bool is_process_table = false);

private:
    uint64_t pgtbl_;
    uint32_t txsz_;
    bool virt_for_fl_;
    uint32_t input_addr_split_;
    uint32_t initial_lkup_level_;
    uint32_t initial_block_split_;

    struct Descriptor {
        uint64_t value;
        DescriptorType dtype;
        uint64_t output_address;
        uint64_t next_level_base_addr_upper;
    };

    Descriptor do_level_lookup(uint64_t table_base_address, uint32_t table_index,
                               bool virtual_addr = false);
    Descriptor do_fl_sl_level_lookup(uint64_t table_base_address, uint32_t table_index,
                                     uint32_t block_split, bool virtual_addr = false);
    Descriptor do_tl_level_lookup(uint64_t table_base_address, uint32_t table_index);

    MemoryAttributes extract_attributes(uint64_t descriptor_value) const noexcept;
    uint64_t extract_output_address(uint64_t descriptor_value, uint32_t n) const noexcept;

    // Helper functions for formatting output (merged from LPAEIommuLib)
    std::string format_mapping(uint64_t vstart, uint64_t vend, const LPAELeafMapping* info) const;
    std::string format_unmapped(uint64_t vstart, uint64_t vend) const;
    std::string get_size_string(uint64_t size) const;
};

#endif // LPAE_PAGETABLE_H_
