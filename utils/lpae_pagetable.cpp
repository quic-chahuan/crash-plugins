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

#include "lpae_pagetable.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <stdexcept>
#include <array>

// ============================================================================
// Bit manipulation helpers - optimized with constexpr
// ============================================================================

constexpr uint64_t extract_bits(uint64_t value, uint32_t msb, uint32_t lsb) noexcept {
    const uint32_t width = msb - lsb + 1;
    const uint64_t mask = (1ULL << width) - 1;
    return (value >> lsb) & mask;
}

constexpr uint64_t bit_mask(uint32_t msb, uint32_t lsb) noexcept {
    const uint32_t width = msb - lsb + 1;
    return ((1ULL << width) - 1) << lsb;
}

// ============================================================================
// MemoryAttributes Implementation - optimized
// ============================================================================

MemoryAttributes::MemoryAttributes()
    : software(0), XN(false), PXN(false), contiguous_hint(false),
      nG(false), AF(false), sh_10(0), ap_21(0), ns(false), attr_index_20(0) {}

std::vector<std::string> MemoryAttributes::get_attribute_strings() const {
    std::vector<std::string> attrs;
    attrs.reserve(10); // Pre-allocate for typical number of attributes

    // Use structured bindings and lookup tables for better performance
    if (XN) attrs.emplace_back("XN");
    if (PXN) attrs.emplace_back("PXN");
    if (contiguous_hint) attrs.emplace_back("Contiguous");
    if (nG) attrs.emplace_back("nG");
    if (AF) attrs.emplace_back("AF");

    // Shareability - use lookup table
    static constexpr std::array<const char*, 4> shareability_names = {
        "Non-shareable", "UNPREDICTABLE", "Outer Shareable", "Inner Shareable"
    };
    attrs.emplace_back(shareability_names[sh_10 & 0x3]);

    // Access permissions - use lookup table
    static constexpr std::array<const char*, 4> access_perm_names = {
        "R/W@PL1", "R/W", "R/O@PL1", "R/O"
    };
    attrs.emplace_back(access_perm_names[ap_21 & 0x3]);

    if (ns) attrs.emplace_back("NS");

    // Use more efficient string formatting
    attrs.emplace_back("AI=0x" + std::to_string(attr_index_20));

    return attrs;
}

bool MemoryAttributes::operator==(const MemoryAttributes& other) const noexcept {
    return software == other.software &&
           XN == other.XN &&
           PXN == other.PXN &&
           contiguous_hint == other.contiguous_hint &&
           nG == other.nG &&
           AF == other.AF &&
           sh_10 == other.sh_10 &&
           ap_21 == other.ap_21 &&
           ns == other.ns &&
           attr_index_20 == other.attr_index_20;
}

// ============================================================================
// LPAELeafMapping Implementation - optimized
// ============================================================================

LPAELeafMapping::LPAELeafMapping(uint64_t virt, uint64_t phys, uint64_t size,
                                 const MemoryAttributes& attrs)
    : virt_addr(virt), phys_addr(phys), page_size(size), attributes(attrs) {}

std::pair<uint64_t, uint64_t> LPAELeafMapping::phys_addr_range() const noexcept {
    return {phys_addr, phys_addr + page_size};
}

std::string LPAELeafMapping::to_string() const {
    const auto range = phys_addr_range();
    const uint64_t pstart = range.first;
    const uint64_t pend = range.second;

    std::ostringstream oss;
    oss << "[0x" << std::hex << std::setw(8) << std::setfill('0') << pstart
        << "-0x" << std::setw(8) << pend << "][";

    const auto attr_strs = attributes.get_attribute_strings();
    for (size_t i = 0; i < attr_strs.size(); ++i) {
        if (i > 0) oss << ",";
        oss << attr_strs[i];
    }
    oss << "]";
    return oss.str();
}

// ============================================================================
// LPAETableMapping Implementation
// ============================================================================

LPAETableMapping::LPAETableMapping(uint64_t addr) : next_table_addr(addr) {}

std::string LPAETableMapping::to_string() const {
    return "[Next Table: 0x" + std::to_string(next_table_addr) + "]";
}

// ============================================================================
// VirtualAddressRegister Implementation - optimized with constexpr
// ============================================================================

VirtualAddressRegister::VirtualAddressRegister(uint64_t addr, uint32_t split)
    : value(addr), input_addr_split(split) {}

uint32_t VirtualAddressRegister::get_fl_index() const noexcept {
    return extract_bits(value, input_addr_split + 26, 30);
}

uint32_t VirtualAddressRegister::get_sl_index() const noexcept {
    return extract_bits(value, 29, 21);
}

uint32_t VirtualAddressRegister::get_tl_index() const noexcept {
    return extract_bits(value, 20, 12);
}

uint32_t VirtualAddressRegister::get_page_offset() const noexcept {
    return extract_bits(value, 11, 0);
}

uint64_t VirtualAddressRegister::get_rest(uint32_t n) const noexcept {
    return extract_bits(value, n - 1, 0);
}

// ============================================================================
// Armv7LPAEMMU Implementation - optimized
// ============================================================================

Armv7LPAEMMU::Armv7LPAEMMU()
    : ParserPlugin(), pgtbl_(0), txsz_(0), virt_for_fl_(false),
      input_addr_split_(0), initial_lkup_level_(0), initial_block_split_(0) {
    // All initialization will be done in parse_long_form_tables
}

MemoryAttributes Armv7LPAEMMU::extract_attributes(uint64_t descriptor_value) const noexcept {
    MemoryAttributes attrs;
    attrs.software = static_cast<uint8_t>(extract_bits(descriptor_value, 58, 55));
    attrs.XN = extract_bits(descriptor_value, 54, 54) != 0;
    attrs.PXN = extract_bits(descriptor_value, 53, 53) != 0;
    attrs.contiguous_hint = extract_bits(descriptor_value, 52, 52) != 0;
    attrs.nG = extract_bits(descriptor_value, 11, 11) != 0;
    attrs.AF = extract_bits(descriptor_value, 10, 10) != 0;
    attrs.sh_10 = static_cast<uint8_t>(extract_bits(descriptor_value, 9, 8));
    attrs.ap_21 = static_cast<uint8_t>(extract_bits(descriptor_value, 7, 6));
    attrs.ns = extract_bits(descriptor_value, 5, 5) != 0;
    attrs.attr_index_20 = static_cast<uint8_t>(extract_bits(descriptor_value, 4, 2));
    return attrs;
}

uint64_t Armv7LPAEMMU::extract_output_address(uint64_t descriptor_value, uint32_t n) const noexcept {
    return extract_bits(descriptor_value, 39, n);
}

Armv7LPAEMMU::Descriptor Armv7LPAEMMU::do_level_lookup(
    uint64_t table_base_address, uint32_t table_index, bool virtual_addr) {

    const uint32_t n = input_addr_split_;
    const uint64_t base = extract_bits(table_base_address, 39, n);
    const uint64_t descriptor_addr = (base << n) | (static_cast<uint64_t>(table_index) << 3);

    // Use ParserPlugin interface for memory reading with better error handling
    uint64_t descriptor_val = 0;
    try {
        if (virtual_addr) {
            descriptor_val = read_ulonglong(descriptor_addr, "page table descriptor", true);
        } else {
            // Convert physical address to virtual address for reading
            const ulong virt_addr = phy_to_virt(descriptor_addr);
            descriptor_val = read_ulonglong(virt_addr, "page table descriptor", true);
        }
    } catch (...) {
        // Return invalid descriptor on read failure
        return {0, DescriptorType::INVALID, 0, 0};
    }

    return {
        descriptor_val,
        static_cast<DescriptorType>(descriptor_val & 0x3),
        0,
        0
    };
}

Armv7LPAEMMU::Descriptor Armv7LPAEMMU::do_fl_sl_level_lookup(
    uint64_t table_base_address, uint32_t table_index,
    uint32_t block_split, bool virtual_addr) {

    auto desc = do_level_lookup(table_base_address, table_index, virtual_addr);

    switch (desc.dtype) {
        case DescriptorType::BLOCK:
            desc.output_address = extract_bits(desc.value, 39, block_split);
            break;
        case DescriptorType::TABLE:
            desc.next_level_base_addr_upper = extract_bits(desc.value, 39, 12);
            break;
        case DescriptorType::INVALID:
            break;
        default:
            throw std::runtime_error("Invalid first- or second-level descriptor type: " +
                                   std::to_string(static_cast<int>(desc.dtype)));
    }

    return desc;
}

Armv7LPAEMMU::Descriptor Armv7LPAEMMU::do_tl_level_lookup(
    uint64_t table_base_address, uint32_t table_index) {

    auto desc = do_level_lookup(table_base_address, table_index, false);

    if (desc.dtype == DescriptorType::TL_PAGE) {
        desc.output_address = extract_bits(desc.value, 39, 12);
    } else if (desc.dtype != DescriptorType::INVALID) {
        throw std::runtime_error("Invalid third-level descriptor type: " +
                               std::to_string(static_cast<int>(desc.dtype)));
    }

    return desc;
}

std::unique_ptr<LPAEMappingInfo> Armv7LPAEMMU::translate_first_level(
    VirtualAddressRegister& virt_r) {

    try {
        const auto fl_desc = do_fl_sl_level_lookup(
            pgtbl_, virt_r.get_fl_index(), 30, virt_for_fl_);

        if (fl_desc.dtype == DescriptorType::INVALID) {
            return nullptr;
        }

        if (fl_desc.dtype == DescriptorType::BLOCK) {
            // 1GB block mapping
            const uint64_t phys = (fl_desc.output_address << 30) | virt_r.get_rest(30);
            const auto attrs = extract_attributes(fl_desc.value);
            return std::make_unique<LPAELeafMapping>(virt_r.value, phys, LPAE_SZ_1G, attrs);
        }

        // Table descriptor
        const uint64_t next_table = fl_desc.next_level_base_addr_upper << 12;
        return std::make_unique<LPAETableMapping>(next_table);

    } catch (const std::exception&) {
        return nullptr;
    }
}

std::unique_ptr<LPAEMappingInfo> Armv7LPAEMMU::translate_second_level(
    VirtualAddressRegister& virt_r, uint64_t level2_table_addr, uint32_t block_split) {

    if (block_split == 0) {
        block_split = initial_block_split_;
    }

    try {
        const auto sl_desc = do_fl_sl_level_lookup(
            level2_table_addr, virt_r.get_sl_index(), block_split, false);

        if (sl_desc.dtype == DescriptorType::INVALID) {
            return nullptr;
        }

        if (sl_desc.dtype == DescriptorType::BLOCK) {
            // 2MB block mapping
            const uint64_t phys = (sl_desc.output_address << block_split) |
                                 virt_r.get_rest(block_split);
            const auto attrs = extract_attributes(sl_desc.value);
            return std::make_unique<LPAELeafMapping>(virt_r.value, phys, LPAE_SZ_2M, attrs);
        }

        // Table descriptor
        const uint64_t next_table = sl_desc.next_level_base_addr_upper << 12;
        return std::make_unique<LPAETableMapping>(next_table);

    } catch (const std::exception&) {
        return nullptr;
    }
}

std::unique_ptr<LPAEMappingInfo> Armv7LPAEMMU::translate_third_level(
    VirtualAddressRegister& virt_r, uint64_t level3_table_addr) {

    try {
        const auto tl_desc = do_tl_level_lookup(level3_table_addr, virt_r.get_tl_index());

        if (tl_desc.dtype == DescriptorType::INVALID) {
            return nullptr;
        }

        // 4KB page mapping
        const uint64_t phys = (tl_desc.output_address << 12) | virt_r.get_rest(12);
        const auto attrs = extract_attributes(tl_desc.value);
        return std::make_unique<LPAELeafMapping>(virt_r.value, phys, LPAE_SZ_4K, attrs);

    } catch (const std::exception&) {
        return nullptr;
    }
}

std::unique_ptr<LPAEMappingInfo> Armv7LPAEMMU::translate(uint64_t virt_addr) {
    VirtualAddressRegister virt_r(virt_addr, input_addr_split_);

    uint64_t level2_table_addr;

    if (initial_lkup_level_ == 1) {
        auto res = translate_first_level(virt_r);
        if (!res || res->is_leaf()) {
            return res;
        }
        level2_table_addr = static_cast<LPAETableMapping*>(res.get())->next_table_addr;
    } else {
        level2_table_addr = pgtbl_;
    }

    auto res = translate_second_level(virt_r, level2_table_addr);
    if (!res || res->is_leaf()) {
        return res;
    }

    const uint64_t level3_table_addr = static_cast<LPAETableMapping*>(res.get())->next_table_addr;
    return translate_third_level(virt_r, level3_table_addr);
}

// ============================================================================
// ParserPlugin interface implementation
// ============================================================================

void Armv7LPAEMMU::cmd_main(void) {
    // This method would be called if this class was used as a standalone plugin
    // For now, it's empty as this class is primarily used as a library
}

void Armv7LPAEMMU::init_command(void) {
    // Initialize command metadata - empty for library usage
}

void Armv7LPAEMMU::init_offset(void) {
    // Initialize field offsets - empty for library usage
}

// ============================================================================
// High-level Analysis Implementation - optimized
// ============================================================================

LPAEMappingMap Armv7LPAEMMU::get_flat_mappings() {
    LPAEMappingMap mappings;
    const uint32_t n = get_input_addr_split();

    // Note: std::map doesn't have reserve() method, unlike std::vector

    // Iterate through all possible page table entries
    for (uint32_t fl_index = 0; fl_index < LPAE_NUM_FL_PTE; ++fl_index) {
        VirtualAddressRegister virt_r(static_cast<uint64_t>(fl_index) << 30, n);

        auto info1 = translate_first_level(virt_r);
        if (!info1) continue;

        if (info1->is_leaf()) {
            const auto* leaf = static_cast<LPAELeafMapping*>(info1.get());
            const uint64_t virt = virt_r.value;
            mappings[{virt, virt + leaf->page_size}] =
                std::make_shared<LPAELeafMapping>(*leaf);
            continue;
        }

        // Second-level lookup
        const uint64_t level2_addr = static_cast<LPAETableMapping*>(info1.get())->next_table_addr;

        for (uint32_t sl_index = 0; sl_index < LPAE_NUM_SL_PTE; ++sl_index) {
            virt_r.value = (static_cast<uint64_t>(fl_index) << 30) |
                          (static_cast<uint64_t>(sl_index) << 21);

            auto info2 = translate_second_level(virt_r, level2_addr);
            if (!info2) continue;

            if (info2->is_leaf()) {
                const auto* leaf = static_cast<LPAELeafMapping*>(info2.get());
                const uint64_t virt = virt_r.value;
                mappings[{virt, virt + leaf->page_size}] =
                    std::make_shared<LPAELeafMapping>(*leaf);
                continue;
            }

            // Third-level lookup
            const uint64_t level3_addr = static_cast<LPAETableMapping*>(info2.get())->next_table_addr;

            for (uint32_t tl_index = 0; tl_index < LPAE_NUM_TL_PTE; ++tl_index) {
                virt_r.value = (static_cast<uint64_t>(fl_index) << 30) |
                              (static_cast<uint64_t>(sl_index) << 21) |
                              (static_cast<uint64_t>(tl_index) << 12);

                auto info3 = translate_third_level(virt_r, level3_addr);
                if (!info3 || !info3->is_leaf()) continue;

                const auto* leaf = static_cast<LPAELeafMapping*>(info3.get());
                const uint64_t virt = virt_r.value;
                mappings[{virt, virt + leaf->page_size}] =
                    std::make_shared<LPAELeafMapping>(*leaf);
            }
        }
    }

    return mappings;
}

LPAEMappingMap Armv7LPAEMMU::get_coalesced_mappings(const LPAEMappingMap& flat_mappings) {
    if (flat_mappings.empty()) {
        return {};
    }

    std::vector<std::pair<LPAEMappingRange, std::shared_ptr<LPAELeafMapping>>> flat_items;
    flat_items.reserve(flat_mappings.size());
    flat_items.assign(flat_mappings.begin(), flat_mappings.end());

    // Mark adjacent equivalent mappings
    std::unordered_map<size_t, uint64_t> samers;
    uint64_t cur_virt = flat_items[0].first.first;

    for (size_t i = 1; i < flat_items.size(); ++i) {
        const auto& current_item = flat_items[i];
        const auto& prev_item = flat_items[i - 1];
        const auto& virt_range = current_item.first;
        const auto& info = current_item.second;
        const auto& prev_range = prev_item.first;
        const auto& prev_info = prev_item.second;

        if (virt_range.first == prev_range.second &&
            info->attributes == prev_info->attributes) {
            samers[i] = cur_virt;
        } else {
            cur_virt = virt_range.first;
        }
    }

    // Merge adjacent equivalent mappings
    std::unordered_map<uint64_t, std::shared_ptr<LPAELeafMapping>> coalesced_by_start;
    coalesced_by_start.reserve(flat_items.size());

    for (size_t i = 0; i < flat_items.size(); ++i) {
        const auto& item = flat_items[i];
        const auto& virt_range = item.first;
        const auto& info = item.second;
        const uint64_t page_size = virt_range.second - virt_range.first;

        const auto it = samers.find(i);
        if (it != samers.end()) {
            coalesced_by_start[it->second]->page_size += page_size;
        } else {
            coalesced_by_start[virt_range.first] = std::make_shared<LPAELeafMapping>(*info);
        }
    }

    // Convert to range-keyed map
    LPAEMappingMap cc;

    for (const auto& pair : coalesced_by_start) {
        const uint64_t virt_start = pair.first;
        const auto& info = pair.second;
        cc[{virt_start, virt_start + info->page_size}] = info;
    }

    // Fill in unmapped gaps efficiently
    if (!cc.empty()) {
        const auto first_vstart = cc.begin()->first.first;
        const auto last_vend = std::prev(cc.end())->first.second;

        if (first_vstart != 0) {
            cc[{0, first_vstart}] = nullptr;
        }

        if (last_vend != 0xFFFFFFFFULL) {
            cc[{last_vend, 0xFFFFFFFFULL}] = nullptr;
        }

        // Fill gaps between mappings
        std::vector<LPAEMappingRange> keys;
        keys.reserve(cc.size());
        for (const auto& pair : cc) {
            keys.push_back(pair.first);
        }
        std::sort(keys.begin(), keys.end());

        for (size_t i = 1; i < keys.size() - 1; ++i) {
            const uint64_t prev_end = keys[i - 1].second;
            const uint64_t curr_start = keys[i].first;
            if (prev_end != curr_start) {
                cc[{prev_end, curr_start}] = nullptr;
            }
        }
    }

    return cc;
}

std::string Armv7LPAEMMU::get_size_string(uint64_t size) const {
    // Use static lookup table for better performance
    static const std::array<std::pair<uint64_t, const char*>, 3> size_map = {{
        {LPAE_SZ_1G, "1G"}, {LPAE_SZ_2M, "2M"}, {LPAE_SZ_4K, "4K"}
    }};

    // Direct lookup for common sizes
    for (const auto& pair : size_map) {
        const uint64_t sz = pair.first;
        const char* name = pair.second;
        if (size == sz) {
            return name;
        }
    }

    // Check for multiples
    for (const auto& pair : size_map) {
        const uint64_t sz = pair.first;
        const char* name = pair.second;
        if (size % sz == 0) {
            const uint64_t mult = size / sz;
            return std::string(name) + "*" + std::to_string(mult);
        }
    }

    return std::to_string(size);
}

std::string Armv7LPAEMMU::format_mapping(uint64_t vstart, uint64_t vend,
                                         const LPAELeafMapping* info) const {
    std::ostringstream oss;
    oss << "[0x" << std::hex << std::setw(8) << std::setfill('0') << vstart
        << "--0x" << std::setw(8) << vend << "] "
        << "[0x" << std::setw(8) << (vend - vstart) << "] "
        << "[A:0x" << std::setw(8) << info->phys_addr
        << "--0x" << std::setw(8) << (info->phys_addr + info->page_size) << "] [";

    const auto attrs = info->attributes.get_attribute_strings();
    for (size_t i = 0; i < attrs.size(); ++i) {
        if (i > 0) oss << ",";
        oss << attrs[i];
    }
    oss << "][" << get_size_string(info->page_size) << "]\n";

    return oss.str();
}

std::string Armv7LPAEMMU::format_unmapped(uint64_t vstart, uint64_t vend) const {
    std::ostringstream oss;
    oss << "[0x" << std::hex << std::setw(8) << std::setfill('0') << vstart
        << "--0x" << std::setw(8) << vend << "] "
        << "[0x" << std::setw(8) << (vend - vstart) << "] [UNMAPPED]\n";
    return oss.str();
}

void Armv7LPAEMMU::print_lpae_mappings(const LPAEMappingMap& mappings,
                                       std::ostream& outfile) const {
    for (const auto& pair : mappings) {
        const auto& range = pair.first;
        const auto& info = pair.second;
        const uint64_t vstart = range.first;
        const uint64_t vend = range.second;
        if (info) {
            outfile << format_mapping(vstart, vend, info.get());
        } else {
            outfile << format_unmapped(vstart, vend);
        }
    }
}

void Armv7LPAEMMU::print_lpae_mappings_direct(const LPAEMappingMap& mappings) const {
    for (const auto& pair : mappings) {
        const auto& range = pair.first;
        const auto& info = pair.second;
        const uint64_t vstart = range.first;
        const uint64_t vend = range.second;
        if (info) {
            PRINT("%s", format_mapping(vstart, vend, info.get()).c_str());
        } else {
            PRINT("%s", format_unmapped(vstart, vend).c_str());
        }
    }
}

bool Armv7LPAEMMU::parse_long_form_tables(uint64_t pg_table,
                                          const std::string& client_name,
                                          bool is_process_table) {
    try {
        // Display appropriate header based on table type
        const char* table_type = is_process_table ? "Process" : "IOMMU";
        PRINT("ARM32 LPAE %s Page Table Analysis\n", table_type);
        PRINT("Client: %s\n", client_name.c_str());
        PRINT("Page Table Base: 0x%lx\n", pg_table);
        PRINT("Virtual Address Space: 32 bits (4GB)\n\n");

        PRINT("[VA Start -- VA End  ] [Size      ] "
              "[PA Start   -- PA End  ] [Attributes][Page Table Entry Size]\n");

        if (pg_table == 0) {
            const char* reason = is_process_table ?
                "Process may not have valid page table" :
                "Probably a secure domain";
            PRINT("No Page Table Found. (%s)\n", reason);
            return true;
        }

        // Initialize parameters for 4GB virtual address space (T0SZ=0)
        pgtbl_ = pg_table;
        txsz_ = 0;  // Fixed to 0 for 4GB virtual address space
        virt_for_fl_ = !is_process_table;  // For process page tables, don't use virtual addressing for first level

        // Fixed parameters for T0SZ=0 (32-bit virtual address space)
        initial_lkup_level_ = 1;
        initial_block_split_ = 12;
        input_addr_split_ = 5;  // 5 - 0 = 5

        const auto flat_mappings = get_flat_mappings();
        if (flat_mappings.empty()) {
            PRINT("No valid mappings found in page table.\n");
            return true;
        }

        const auto coalesced = get_coalesced_mappings(flat_mappings);

        // Print coalesced mappings first (more readable)
        PRINT("=== Coalesced Mappings ===\n");
        print_lpae_mappings_direct(coalesced);

        // Print raw mappings for detailed analysis
        PRINT("\n=== Raw Mappings (Detailed) ===\n");
        print_lpae_mappings_direct(flat_mappings);

        // Print summary statistics
        PRINT("\n=== Summary ===\n");
        PRINT("Total mappings: %zu\n", flat_mappings.size());
        PRINT("Coalesced mappings: %zu\n", coalesced.size());

        // Calculate total mapped memory
        uint64_t total_mapped = 0;
        for (const auto& pair : flat_mappings) {
            const auto& range = pair.first;
            total_mapped += (range.second - range.first);
        }
        PRINT("Total mapped memory: 0x%lx (%lu MB)\n",
              total_mapped, (total_mapped / (1024 * 1024)));

        return true;

    } catch (const std::exception& e) {
        PRINT("Error parsing ARM32 LPAE page tables: %s\n", e.what());
        return false;
    }
}
