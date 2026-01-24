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

#ifndef LPAE_IOMMU_LIB_H
#define LPAE_IOMMU_LIB_H

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>

namespace lpae_iommu {

// Constants for page table structure
constexpr size_t NUM_FL_PTE = 4;      // First-level page table entries
constexpr size_t NUM_SL_PTE = 512;    // Second-level page table entries
constexpr size_t NUM_TL_PTE = 512;    // Third-level page table entries

// Page sizes
constexpr uint64_t SZ_4K = 0x1000;
constexpr uint64_t SZ_2M = 0x200000;
constexpr uint64_t SZ_1G = 0x40000000;

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
    bool operator==(const MemoryAttributes& other) const;
};

// Mapping information base class
class MappingInfo {
public:
    virtual ~MappingInfo() = default;
    virtual bool is_leaf() const = 0;
};

// Leaf mapping (actual memory mapping)
class LeafMapping : public MappingInfo {
public:
    uint64_t virt_addr;
    uint64_t phys_addr;
    uint64_t page_size;
    MemoryAttributes attributes;

    LeafMapping(uint64_t virt, uint64_t phys, uint64_t size,
                const MemoryAttributes& attrs);

    bool is_leaf() const override { return true; }
    std::pair<uint64_t, uint64_t> phys_addr_range() const;
    std::string to_string() const;
};

// Table mapping (pointer to next level)
class TableMapping : public MappingInfo {
public:
    uint64_t next_table_addr;

    explicit TableMapping(uint64_t addr);
    bool is_leaf() const override { return false; }
    std::string to_string() const;
};

// Virtual address register for index extraction
class VirtualAddressRegister {
public:
    uint64_t value;
    uint32_t input_addr_split;

    VirtualAddressRegister(uint64_t addr, uint32_t split);

    uint32_t get_fl_index() const;
    uint32_t get_sl_index() const;
    uint32_t get_tl_index() const;
    uint32_t get_page_offset() const;
    uint64_t get_rest(uint32_t n) const;
};

// Memory reader interface - to be implemented by the caller
class IMemoryReader {
public:
    virtual ~IMemoryReader() = default;
    virtual uint64_t read_dword(uint64_t address, bool virtual_addr = false) = 0;
    virtual bool is_valid_address(uint64_t address) = 0;
};

// ARMv7 LPAE MMU implementation
class Armv7LPAEMMU {
public:
    Armv7LPAEMMU(IMemoryReader* reader, uint64_t pgtbl, uint32_t txsz,
                 bool virt_for_fl = false);

    // Main translation function
    std::unique_ptr<MappingInfo> translate(uint64_t virt_addr);

    // Level-specific translation functions
    std::unique_ptr<MappingInfo> translate_first_level(VirtualAddressRegister& virt_r);
    std::unique_ptr<MappingInfo> translate_second_level(VirtualAddressRegister& virt_r,
                                                         uint64_t level2_table_addr,
                                                         uint32_t block_split = 0);
    std::unique_ptr<MappingInfo> translate_third_level(VirtualAddressRegister& virt_r,
                                                        uint64_t level3_table_addr);

    uint32_t get_input_addr_split() const { return input_addr_split_; }

private:
    IMemoryReader* reader_;
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

    MemoryAttributes extract_attributes(uint64_t descriptor_value);
    uint64_t extract_output_address(uint64_t descriptor_value, uint32_t n);
};

// Mapping range type: (virt_start, virt_end) -> LeafMapping or nullptr (unmapped)
using MappingRange = std::pair<uint64_t, uint64_t>;
using MappingMap = std::map<MappingRange, std::shared_ptr<LeafMapping>>;

// Main library functions
class LPAEIommuLib {
public:
    // Get flat (uncoalesced) mappings from page tables
    static MappingMap get_flat_mappings(IMemoryReader* reader,
                                        uint64_t pg_table,
                                        uint32_t t0sz = 0);

    // Coalesce contiguous mappings with same attributes
    static MappingMap get_coalesced_mappings(const MappingMap& flat_mappings);

    // Print mappings to output stream
    static void print_lpae_mappings(const MappingMap& mappings,
                                    std::ostream& outfile);

    // Parse and dump page tables (main entry point)
    static bool parse_long_form_tables(IMemoryReader* reader,
                                       uint64_t pg_table,
                                       uint32_t domain_num,
                                       const std::string& client_name,
                                       const std::string& iommu_context,
                                       const std::string& redirect_status,
                                       std::ostream& outfile);

private:
    static std::string format_mapping(uint64_t vstart, uint64_t vend,
                                     const LeafMapping* info);
    static std::string format_unmapped(uint64_t vstart, uint64_t vend);
    static std::string get_size_string(uint64_t size);
};

} // namespace lpae_iommu

#endif // LPAE_IOMMU_LIB_H
