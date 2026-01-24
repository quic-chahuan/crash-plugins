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

#include "lpae_iommu_lib.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <stdexcept>

namespace lpae_iommu {

// Bit manipulation helpers
static inline uint64_t extract_bits(uint64_t value, uint32_t msb, uint32_t lsb) {
    uint32_t width = msb - lsb + 1;
    uint64_t mask = (1ULL << width) - 1;
    return (value >> lsb) & mask;
}

static inline uint64_t bit_mask(uint32_t msb, uint32_t lsb) {
    uint32_t width = msb - lsb + 1;
    return ((1ULL << width) - 1) << lsb;
}

// ============================================================================
// MemoryAttributes Implementation
// ============================================================================

MemoryAttributes::MemoryAttributes()
    : software(0), XN(false), PXN(false), contiguous_hint(false),
      nG(false), AF(false), sh_10(0), ap_21(0), ns(false), attr_index_20(0) {}

std::vector<std::string> MemoryAttributes::get_attribute_strings() const {
    std::vector<std::string> attrs;

    if (XN) attrs.push_back("XN");
    if (PXN) attrs.push_back("PXN");
    if (contiguous_hint) attrs.push_back("Contiguous");
    if (nG) attrs.push_back("nG");
    if (AF) attrs.push_back("AF");

    // Shareability
    switch (sh_10) {
        case 0b00: attrs.push_back("Non-shareable"); break;
        case 0b01: attrs.push_back("UNPREDICTABLE"); break;
        case 0b10: attrs.push_back("Outer Shareable"); break;
        case 0b11: attrs.push_back("Inner Shareable"); break;
    }

    // Access permissions
    switch (ap_21) {
        case 0b00: attrs.push_back("R/W@PL1"); break;
        case 0b01: attrs.push_back("R/W"); break;
        case 0b10: attrs.push_back("R/O@PL1"); break;
        case 0b11: attrs.push_back("R/O"); break;
    }

    if (ns) attrs.push_back("NS");

    std::ostringstream oss;
    oss << "AI=0x" << std::hex << static_cast<int>(attr_index_20);
    attrs.push_back(oss.str());

    return attrs;
}

bool MemoryAttributes::operator==(const MemoryAttributes& other) const {
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
// LeafMapping Implementation
// ============================================================================

LeafMapping::LeafMapping(uint64_t virt, uint64_t phys, uint64_t size,
                         const MemoryAttributes& attrs)
    : virt_addr(virt), phys_addr(phys), page_size(size), attributes(attrs) {}

std::pair<uint64_t, uint64_t> LeafMapping::phys_addr_range() const {
    return {phys_addr, phys_addr + page_size};
}

std::string LeafMapping::to_string() const {
    auto [pstart, pend] = phys_addr_range();
    std::ostringstream oss;
    oss << "[0x" << std::hex << std::setw(8) << std::setfill('0') << pstart
        << "-0x" << std::setw(8) << pend << "][";

    auto attr_strs = attributes.get_attribute_strings();
    for (size_t i = 0; i < attr_strs.size(); ++i) {
        if (i > 0) oss << ",";
        oss << attr_strs[i];
    }
    oss << "]";
    return oss.str();
}

// ============================================================================
// TableMapping Implementation
// ============================================================================

TableMapping::TableMapping(uint64_t addr) : next_table_addr(addr) {}

std::string TableMapping::to_string() const {
    std::ostringstream oss;
    oss << "[Next Table: 0x" << std::hex << next_table_addr << "]";
    return oss.str();
}

// ============================================================================
// VirtualAddressRegister Implementation
// ============================================================================

VirtualAddressRegister::VirtualAddressRegister(uint64_t addr, uint32_t split)
    : value(addr), input_addr_split(split) {}

uint32_t VirtualAddressRegister::get_fl_index() const {
    return extract_bits(value, input_addr_split + 26, 30);
}

uint32_t VirtualAddressRegister::get_sl_index() const {
    return extract_bits(value, 29, 21);
}

uint32_t VirtualAddressRegister::get_tl_index() const {
    return extract_bits(value, 20, 12);
}

uint32_t VirtualAddressRegister::get_page_offset() const {
    return extract_bits(value, 11, 0);
}

uint64_t VirtualAddressRegister::get_rest(uint32_t n) const {
    return extract_bits(value, n - 1, 0);
}

// ============================================================================
// Armv7LPAEMMU Implementation
// ============================================================================

Armv7LPAEMMU::Armv7LPAEMMU(IMemoryReader* reader, uint64_t pgtbl,
                           uint32_t txsz, bool virt_for_fl)
    : reader_(reader), pgtbl_(pgtbl), txsz_(txsz), virt_for_fl_(virt_for_fl) {

    if ((32 - txsz) > 30) {
        initial_lkup_level_ = 1;
        initial_block_split_ = 12;
        input_addr_split_ = 5 - txsz;
        if (input_addr_split_ != 4 && input_addr_split_ != 5) {
            throw std::runtime_error("Invalid stage 1 first-level 'n' value");
        }
    } else {
        initial_lkup_level_ = 2;
        initial_block_split_ = 21;
        input_addr_split_ = 14 - txsz;
        if (input_addr_split_ < 7 || input_addr_split_ > 12) {
            throw std::runtime_error("Invalid stage 1 second-level (initial) 'n' value");
        }
    }
}

MemoryAttributes Armv7LPAEMMU::extract_attributes(uint64_t descriptor_value) {
    MemoryAttributes attrs;
    attrs.software = extract_bits(descriptor_value, 58, 55);
    attrs.XN = extract_bits(descriptor_value, 54, 54) != 0;
    attrs.PXN = extract_bits(descriptor_value, 53, 53) != 0;
    attrs.contiguous_hint = extract_bits(descriptor_value, 52, 52) != 0;
    attrs.nG = extract_bits(descriptor_value, 11, 11) != 0;
    attrs.AF = extract_bits(descriptor_value, 10, 10) != 0;
    attrs.sh_10 = extract_bits(descriptor_value, 9, 8);
    attrs.ap_21 = extract_bits(descriptor_value, 7, 6);
    attrs.ns = extract_bits(descriptor_value, 5, 5) != 0;
    attrs.attr_index_20 = extract_bits(descriptor_value, 4, 2);
    return attrs;
}

uint64_t Armv7LPAEMMU::extract_output_address(uint64_t descriptor_value, uint32_t n) {
    return extract_bits(descriptor_value, 39, n);
}

Armv7LPAEMMU::Descriptor Armv7LPAEMMU::do_level_lookup(
    uint64_t table_base_address, uint32_t table_index, bool virtual_addr) {

    uint32_t n = input_addr_split_;
    uint64_t base = extract_bits(table_base_address, 39, n);
    uint64_t descriptor_addr = (base << n) | (static_cast<uint64_t>(table_index) << 3);

    uint64_t descriptor_val = reader_->read_dword(descriptor_addr, virtual_addr);

    Descriptor desc;
    desc.value = descriptor_val;
    desc.dtype = static_cast<DescriptorType>(descriptor_val & 0x3);
    desc.output_address = 0;
    desc.next_level_base_addr_upper = 0;

    return desc;
}

Armv7LPAEMMU::Descriptor Armv7LPAEMMU::do_fl_sl_level_lookup(
    uint64_t table_base_address, uint32_t table_index,
    uint32_t block_split, bool virtual_addr) {

    Descriptor desc = do_level_lookup(table_base_address, table_index, virtual_addr);

    if (desc.dtype == DescriptorType::BLOCK) {
        desc.output_address = extract_bits(desc.value, 39, block_split);
    } else if (desc.dtype == DescriptorType::TABLE) {
        desc.next_level_base_addr_upper = extract_bits(desc.value, 39, 12);
    } else if (desc.dtype != DescriptorType::INVALID) {
        throw std::runtime_error("Invalid first- or second-level descriptor");
    }

    return desc;
}

Armv7LPAEMMU::Descriptor Armv7LPAEMMU::do_tl_level_lookup(
    uint64_t table_base_address, uint32_t table_index) {

    Descriptor desc = do_level_lookup(table_base_address, table_index, false);

    if (desc.dtype == DescriptorType::TL_PAGE) {
        desc.output_address = extract_bits(desc.value, 39, 12);
    } else if (desc.dtype != DescriptorType::INVALID) {
        throw std::runtime_error("Invalid third-level descriptor");
    }

    return desc;
}

std::unique_ptr<MappingInfo> Armv7LPAEMMU::translate_first_level(
    VirtualAddressRegister& virt_r) {

    try {
        Descriptor fl_desc = do_fl_sl_level_lookup(
            pgtbl_, virt_r.get_fl_index(), 30, virt_for_fl_);

        if (fl_desc.dtype == DescriptorType::INVALID) {
            return nullptr;
        }

        if (fl_desc.dtype == DescriptorType::BLOCK) {
            // 1GB block mapping
            uint64_t phys = (fl_desc.output_address << 30) | virt_r.get_rest(30);
            MemoryAttributes attrs = extract_attributes(fl_desc.value);
            return std::make_unique<LeafMapping>(virt_r.value, phys, SZ_1G, attrs);
        }

        // Table descriptor
        uint64_t next_table = fl_desc.next_level_base_addr_upper << 12;
        return std::make_unique<TableMapping>(next_table);

    } catch (...) {
        return nullptr;
    }
}

std::unique_ptr<MappingInfo> Armv7LPAEMMU::translate_second_level(
    VirtualAddressRegister& virt_r, uint64_t level2_table_addr, uint32_t block_split) {

    if (block_split == 0) {
        block_split = initial_block_split_;
    }

    try {
        Descriptor sl_desc = do_fl_sl_level_lookup(
            level2_table_addr, virt_r.get_sl_index(), block_split, false);

        if (sl_desc.dtype == DescriptorType::INVALID) {
            return nullptr;
        }

        if (sl_desc.dtype == DescriptorType::BLOCK) {
            // 2MB block mapping
            uint64_t phys = (sl_desc.output_address << block_split) |
                           virt_r.get_rest(block_split);
            MemoryAttributes attrs = extract_attributes(sl_desc.value);
            return std::make_unique<LeafMapping>(virt_r.value, phys, SZ_2M, attrs);
        }

        // Table descriptor
        uint64_t next_table = sl_desc.next_level_base_addr_upper << 12;
        return std::make_unique<TableMapping>(next_table);

    } catch (...) {
        return nullptr;
    }
}

std::unique_ptr<MappingInfo> Armv7LPAEMMU::translate_third_level(
    VirtualAddressRegister& virt_r, uint64_t level3_table_addr) {

    try {
        Descriptor tl_desc = do_tl_level_lookup(
            level3_table_addr, virt_r.get_tl_index());

        if (tl_desc.dtype == DescriptorType::INVALID) {
            return nullptr;
        }

        // 4KB page mapping
        uint64_t phys = (tl_desc.output_address << 12) | virt_r.get_rest(12);
        MemoryAttributes attrs = extract_attributes(tl_desc.value);
        return std::make_unique<LeafMapping>(virt_r.value, phys, SZ_4K, attrs);

    } catch (...) {
        return nullptr;
    }
}

std::unique_ptr<MappingInfo> Armv7LPAEMMU::translate(uint64_t virt_addr) {
    VirtualAddressRegister virt_r(virt_addr, input_addr_split_);

    uint64_t level2_table_addr;

    if (initial_lkup_level_ == 1) {
        auto res = translate_first_level(virt_r);
        if (!res || res->is_leaf()) {
            return res;
        }
        level2_table_addr = static_cast<TableMapping*>(res.get())->next_table_addr;
    } else {
        level2_table_addr = pgtbl_;
    }

    auto res = translate_second_level(virt_r, level2_table_addr);
    if (!res || res->is_leaf()) {
        return res;
    }

    uint64_t level3_table_addr = static_cast<TableMapping*>(res.get())->next_table_addr;
    return translate_third_level(virt_r, level3_table_addr);
}

// ============================================================================
// LPAEIommuLib Implementation
// ============================================================================

MappingMap LPAEIommuLib::get_flat_mappings(IMemoryReader* reader,
                                           uint64_t pg_table,
                                           uint32_t t0sz) {
    MappingMap mappings;
    Armv7LPAEMMU mmu(reader, pg_table, t0sz, true);
    uint32_t n = mmu.get_input_addr_split();

    // Iterate through all possible page table entries
    for (uint32_t fl_index = 0; fl_index < NUM_FL_PTE; ++fl_index) {
        VirtualAddressRegister virt_r(0, n);
        virt_r.value = static_cast<uint64_t>(fl_index) << 30;

        auto info1 = mmu.translate_first_level(virt_r);
        if (!info1) continue;

        if (info1->is_leaf()) {
            auto* leaf = static_cast<LeafMapping*>(info1.get());
            uint64_t virt = virt_r.value;
            mappings[{virt, virt + leaf->page_size}] =
                std::make_shared<LeafMapping>(*leaf);
            continue;
        }

        // Second-level lookup
        uint64_t level2_addr = static_cast<TableMapping*>(info1.get())->next_table_addr;

        for (uint32_t sl_index = 0; sl_index < NUM_SL_PTE; ++sl_index) {
            virt_r.value = (static_cast<uint64_t>(fl_index) << 30) |
                          (static_cast<uint64_t>(sl_index) << 21);

            auto info2 = mmu.translate_second_level(virt_r, level2_addr);
            if (!info2) continue;

            if (info2->is_leaf()) {
                auto* leaf = static_cast<LeafMapping*>(info2.get());
                uint64_t virt = virt_r.value;
                mappings[{virt, virt + leaf->page_size}] =
                    std::make_shared<LeafMapping>(*leaf);
                continue;
            }

            // Third-level lookup
            uint64_t level3_addr = static_cast<TableMapping*>(info2.get())->next_table_addr;

            for (uint32_t tl_index = 0; tl_index < NUM_TL_PTE; ++tl_index) {
                virt_r.value = (static_cast<uint64_t>(fl_index) << 30) |
                              (static_cast<uint64_t>(sl_index) << 21) |
                              (static_cast<uint64_t>(tl_index) << 12);

                auto info3 = mmu.translate_third_level(virt_r, level3_addr);
                if (!info3) continue;

                if (!info3->is_leaf()) {
                    throw std::runtime_error("Non-leaf third-level PTE");
                }

                auto* leaf = static_cast<LeafMapping*>(info3.get());
                uint64_t virt = virt_r.value;
                mappings[{virt, virt + leaf->page_size}] =
                    std::make_shared<LeafMapping>(*leaf);
            }
        }
    }

    return mappings;
}

MappingMap LPAEIommuLib::get_coalesced_mappings(const MappingMap& flat_mappings) {
    if (flat_mappings.empty()) {
        return MappingMap();
    }

    std::vector<std::pair<MappingRange, std::shared_ptr<LeafMapping>>> flat_items(
        flat_mappings.begin(), flat_mappings.end());

    // Mark adjacent equivalent mappings
    std::map<size_t, uint64_t> samers;
    uint64_t cur_virt = flat_items[0].first.first;

    for (size_t i = 1; i < flat_items.size(); ++i) {
        auto [virt_range, info] = flat_items[i];
        auto [virt_start, virt_end] = virt_range;
        auto [prev_range, prev_info] = flat_items[i - 1];
        auto [prev_start, prev_end] = prev_range;

        if (virt_start == prev_end &&
            info->attributes == prev_info->attributes) {
            samers[i] = cur_virt;
        } else {
            cur_virt = virt_start;
        }
    }

    // Merge adjacent equivalent mappings
    std::map<uint64_t, std::shared_ptr<LeafMapping>> coalesced_by_start;

    for (size_t i = 0; i < flat_items.size(); ++i) {
        auto [virt_range, info] = flat_items[i];
        auto [virt_start, virt_end] = virt_range;
        uint64_t page_size = virt_end - virt_start;

        if (samers.count(i)) {
            coalesced_by_start[samers[i]]->page_size += page_size;
        } else {
            coalesced_by_start[virt_start] = std::make_shared<LeafMapping>(*info);
        }
    }

    // Convert to range-keyed map
    MappingMap cc;
    for (const auto& [virt_start, info] : coalesced_by_start) {
        cc[{virt_start, virt_start + info->page_size}] = info;
    }

    // Fill in unmapped gaps
    if (!cc.empty()) {
        auto first = cc.begin();
        auto last = std::prev(cc.end());

        uint64_t first_vstart = first->first.first;
        uint64_t last_vend = last->first.second;

        if (first_vstart != 0) {
            cc[{0, first_vstart}] = nullptr;
        }

        if (last_vend != 0xFFFFFFFFULL) {
            cc[{last_vend, 0xFFFFFFFFULL}] = nullptr;
        }

        // Fill gaps between mappings
        std::vector<MappingRange> keys;
        for (const auto& [range, _] : cc) {
            keys.push_back(range);
        }
        std::sort(keys.begin(), keys.end());

        for (size_t i = 1; i < keys.size() - 1; ++i) {
            uint64_t prev_end = keys[i - 1].second;
            uint64_t curr_start = keys[i].first;
            if (prev_end != curr_start) {
                cc[{prev_end, curr_start}] = nullptr;
            }
        }
    }

    return cc;
}

std::string LPAEIommuLib::get_size_string(uint64_t size) {
    const std::map<uint64_t, std::string> size_map = {
        {SZ_1G, "1G"}, {SZ_2M, "2M"}, {SZ_4K, "4K"}
    };

    if (size_map.count(size)) {
        return size_map.at(size);
    }

    for (auto it = size_map.rbegin(); it != size_map.rend(); ++it) {
        if (size % it->first == 0) {
            uint64_t mult = size / it->first;
            return it->second + "*" + std::to_string(mult);
        }
    }

    return std::to_string(size);
}

std::string LPAEIommuLib::format_mapping(uint64_t vstart, uint64_t vend,
                                         const LeafMapping* info) {
    std::ostringstream oss;
    oss << "[0x" << std::hex << std::setw(8) << std::setfill('0') << vstart
        << "--0x" << std::setw(8) << vend << "] "
        << "[0x" << std::setw(8) << (vend - vstart) << "] "
        << "[A:0x" << std::setw(8) << info->phys_addr
        << "--0x" << std::setw(8) << (info->phys_addr + info->page_size) << "] [";

    auto attrs = info->attributes.get_attribute_strings();
    for (size_t i = 0; i < attrs.size(); ++i) {
        if (i > 0) oss << ",";
        oss << attrs[i];
    }
    oss << "][" << get_size_string(info->page_size) << "]\n";

    return oss.str();
}

std::string LPAEIommuLib::format_unmapped(uint64_t vstart, uint64_t vend) {
    std::ostringstream oss;
    oss << "[0x" << std::hex << std::setw(8) << std::setfill('0') << vstart
        << "--0x" << std::setw(8) << vend << "] "
        << "[0x" << std::setw(8) << (vend - vstart) << "] [UNMAPPED]\n";
    return oss.str();
}

void LPAEIommuLib::print_lpae_mappings(const MappingMap& mappings,
                                       std::ostream& outfile) {
    for (const auto& [range, info] : mappings) {
        auto [vstart, vend] = range;
        if (info) {
            outfile << format_mapping(vstart, vend, info.get());
        } else {
            outfile << format_unmapped(vstart, vend);
        }
    }
}

bool LPAEIommuLib::parse_long_form_tables(IMemoryReader* reader,
                                          uint64_t pg_table,
                                          uint32_t domain_num,
                                          const std::string& client_name,
                                          const std::string& iommu_context,
                                          const std::string& redirect_status,
                                          std::ostream& outfile) {
    try {
        outfile << "IOMMU Context: " << iommu_context
                << ". Domain: " << client_name << " (" << domain_num
                << ") [L2 cache redirect for page tables is "
                << redirect_status << "]\n";

        outfile << "[VA Start -- VA End  ] [Size      ] "
                << "[PA Start   -- PA End  ] [Attributes][Page Table Entry Size]\n";

        if (pg_table == 0) {
            outfile << "No Page Table Found. (Probably a secure domain)\n";
            return true;
        }

        auto flat_mappings = get_flat_mappings(reader, pg_table, 0);
        auto coalesced = get_coalesced_mappings(flat_mappings);

        print_lpae_mappings(coalesced, outfile);

        outfile << "\n-------------\nRAW Dump\n";
        print_lpae_mappings(flat_mappings, outfile);

        return true;

    } catch (const std::exception& e) {
        outfile << "Error parsing page tables: " << e.what() << "\n";
        return false;
    }
}

} // namespace lpae_iommu
