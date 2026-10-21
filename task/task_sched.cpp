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

#include "task_sched.h"
#include <limits>
#include <map>
#include <set>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(TaskSched)
#endif

namespace {
enum class TimeUnit {
    SEC,
    MS,
};

std::string format_ns_value(long double ns, TimeUnit unit) {
    long double divisor = 1000000.0L;
    switch (unit) {
        case TimeUnit::SEC:
            divisor = 1000000000.0L;
            break;
        case TimeUnit::MS:
            divisor = 1000000.0L;
            break;
    }

    std::ostringstream tmp;
    tmp << std::fixed << std::setprecision(6) << (ns / divisor);
    return tmp.str();
}
}

void TaskSched::cmd_main(void) {
    int c;
    std::string cppString;
    bool throttle_mode = false;
    bool has_cpu = false;
    int cpu = -1;

    if (argcnt < 2) {
        cmd_usage(pc->curcmd, SYNOPSIS);
        return;
    }
    argerrs = 0;
    optind = 0;
    opterr = 0;
    optarg = nullptr;

    auto parse_cpu = [](const std::string& value, int& parsed) {
        if (value.empty() || !std::all_of(value.begin(), value.end(), [](char ch) {
                return ch >= '0' && ch <= '9';
            })) {
            return false;
        }
        try {
            size_t pos = 0;
            parsed = std::stoi(value, &pos);
            return pos == value.size();
        } catch (const std::exception&) {
            return false;
        }
    };

    while ((c = getopt(argcnt, args, "Tc:")) != EOF) {
        switch(c) {
            case 'T':
                throttle_mode = true;
                break;
            case 'c':
            {
                cppString.assign(optarg);
                if (!parse_cpu(cppString, cpu) || !is_valid_cpu(cpu)) {
                    PRINT("invalid value: %s\n", cppString.c_str());
                    argerrs++;
                    continue;
                }
                has_cpu = true;
                break;
            }
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs) {
        cmd_usage(pc->curcmd, SYNOPSIS);
        return;
    }

    if (throttle_mode && has_cpu) {
        PRINT("unsupported options: do not use -c with -T, use 'sched -T <cpu>'.\n");
        cmd_usage(pc->curcmd, SYNOPSIS);
        return;
    }

    if (throttle_mode && !has_cpu && optind < argcnt) {
        cppString.assign(args[optind]);
        if (!parse_cpu(cppString, cpu) || !is_valid_cpu(cpu)) {
            PRINT("invalid cpu value: %s\n", cppString.c_str());
            cmd_usage(pc->curcmd, SYNOPSIS);
            return;
        }
        has_cpu = true;
        optind++;
    }

    if (optind < argcnt) {
        PRINT("unexpected argument: %s\n", args[optind]);
        cmd_usage(pc->curcmd, SYNOPSIS);
        return;
    }

    if (throttle_mode) {
        print_throttle_overview(has_cpu ? cpu : -1, true);
        return;
    }

    if (!has_cpu) {
        cmd_usage(pc->curcmd, SYNOPSIS);
        return;
    }

    print_task_timestamps(cpu);
}

void TaskSched::init_command(void) {
    cmd_name = "sched";
    help_str_list={
        "sched",                            /* command name */
        "dump task sched information",        /* short description */
        "-c <cpu> | -T [cpu]\n"
            "  This command dumps the task sched info.\n"
            "  -c <cpu>      show task scheduling table for one CPU + throttle summary\n"
            "  -T            show detailed CFS/RT throttle view for all CPUs\n"
            "  -T <cpu>      show detailed CFS/RT throttle view for one CPU",
        "\n",
        "EXAMPLES",
        "  Display task sched info:",
        "    %s> sched -c 1 ",
        "    Name                 pid     cpu   Exec_Started    Last_Queued     Total_wait_time times_exec Prio  Policy Throttle BudgetLeft(ms)",
        "    swapper/3            0       3     0               0               0               0          120   CFS    No       0.000",
        "\n",
        "  Display throttle overview:",
        "    %s> sched -T",
        "    %s> sched -T 3",
        "\n",
    };
}

TaskSched::TaskSched(){}

void TaskSched::init_offset(void) {
    field_init(task_struct, sched_info);
    field_init(task_struct, prio);
    field_init(task_struct, policy);
    field_init(task_struct, last_enqueued_ts);
    field_init(task_struct, last_sleep_ts);
    field_init(task_struct, wts);
    field_init(task_struct, android_vendor_data1);
    field_init(task_struct, se);
    field_init(task_struct, rt);

    field_init(sched_info, last_arrival);
    field_init(sched_info, last_queued);
    field_init(sched_info, pcount);
    field_init(sched_info, run_delay);
    struct_init(sched_info);

    field_init(walt_task_struct, last_enqueued_ts);
    field_init(walt_task_struct, last_sleep_ts);
    struct_init(walt_task_struct);

    field_init(sched_entity, cfs_rq);
    field_init(sched_rt_entity, rt_rq);

    field_init(rq, nr_running);
    field_init(rq, cfs);
    field_init(rq, rt);
    field_init(runqueue, nr_running);
    field_init(runqueue, cfs);
    field_init(runqueue, rt);

    field_init(task_group, list);
    field_init(task_group, cfs_rq);
    field_init(task_group, rt_rq);
    field_init(task_group, cfs_bandwidth);
    field_init(task_group, rt_bandwidth);
    field_init(task_group, css);

    field_init(cgroup_subsys_state, cgroup);
    field_init(cgroup, kn);
    field_init(kernfs_node, parent);
    field_init(kernfs_node, name);
    field_init(list_head, next);

    field_init(cfs_rq, throttled);
    field_init(cfs_rq, runtime_remaining);
    field_init(cfs_rq, throttle_count);
    field_init(cfs_rq, nr_running);
    field_init(cfs_rq, tg);

    field_init(rt_rq, rt_throttled);
    field_init(rt_rq, rt_time);
    field_init(rt_rq, rt_runtime);
    field_init(rt_rq, rt_nr_boosted);
    field_init(rt_rq, tg);

    field_init(cfs_bandwidth, period);
    field_init(cfs_bandwidth, quota);
    field_init(cfs_bandwidth, period_active);
    field_init(cfs_bandwidth, nr_periods);
    field_init(cfs_bandwidth, nr_throttled);
    field_init(cfs_bandwidth, throttled_time);
    field_init(cfs_bandwidth, period_timer);

    field_init(rt_bandwidth, rt_period);
    field_init(rt_bandwidth, rt_period_active);
    field_init(rt_bandwidth, rt_period_timer);

    field_init(hrtimer, node);
    field_init(hrtimer, function);
    field_init(hrtimer, base);
    field_init(hrtimer, state);
    field_init(hrtimer, is_soft);
    field_init(hrtimer, is_hard);
    field_init(timerqueue_node, expires);
}

void TaskSched::print_task_timestamps(int cpu){
    // Cache field offsets and config values outside the loop
    const int off_sched_info    = field_offset(task_struct, sched_info);
    const int off_last_arrival  = field_offset(sched_info, last_arrival);
    const int off_last_queued   = field_offset(sched_info, last_queued);
    const int off_pcount        = field_offset(sched_info, pcount);
    const int off_run_delay     = field_offset(sched_info, run_delay);
    const int off_last_enq_ts   = field_offset(task_struct, last_enqueued_ts);
    const int off_last_sleep_ts = field_offset(task_struct, last_sleep_ts);
    const int off_wts           = field_offset(task_struct, wts);
    const int off_avd1          = field_offset(task_struct, android_vendor_data1);
    const int off_walt_enq      = field_offset(walt_task_struct, last_enqueued_ts);
    const int off_walt_sleep    = field_offset(walt_task_struct, last_sleep_ts);
    const int off_prio          = field_offset(task_struct, prio);
    const int off_policy        = field_offset(task_struct, policy);
    const int off_task_se       = field_offset(task_struct, se);
    const int off_task_rt       = field_offset(task_struct, rt);
    const int off_se_cfs_rq     = field_offset(sched_entity, cfs_rq);
    const int off_cfs_throttled = field_offset(cfs_rq, throttled);
    const int off_cfs_runtime_remaining = field_offset(cfs_rq, runtime_remaining);
    const int off_cfs_throttle_count = field_offset(cfs_rq, throttle_count);
    const int off_rt_rt_rq      = field_offset(sched_rt_entity, rt_rq);
    const int off_rt_throttled  = field_offset(rt_rq, rt_throttled);
    const int off_rt_time       = field_offset(rt_rq, rt_time);
    const int off_rt_runtime    = field_offset(rt_rq, rt_runtime);
    const bool has_sched_info = struct_size(sched_info) != -1 &&
                                off_sched_info >= 0 && off_last_arrival >= 0 &&
                                off_last_queued >= 0 && off_pcount >= 0 &&
                                off_run_delay >= 0;
    const bool is_walt = get_config_val("CONFIG_SCHED_WALT") == "y" &&
                         struct_size(walt_task_struct) != -1 &&
                         off_walt_enq >= 0 && off_walt_sleep >= 0 &&
                         (off_wts >= 0 || off_avd1 >= 0);
    const bool has_cfs_bw = get_config_val("CONFIG_CFS_BANDWIDTH") == "y" &&
                            get_config_val("CONFIG_FAIR_GROUP_SCHED") == "y" &&
                            off_task_se >= 0 && off_se_cfs_rq >= 0 &&
                            off_cfs_throttled >= 0 &&
                            off_cfs_runtime_remaining >= 0 &&
                            off_cfs_throttle_count >= 0;
    const bool has_rt_bw = get_config_val("CONFIG_RT_GROUP_SCHED") == "y" &&
                           off_task_rt >= 0 && off_rt_rt_rq >= 0 &&
                           off_rt_throttled >= 0 && off_rt_time >= 0 &&
                           off_rt_runtime >= 0;
    std::vector<std::shared_ptr<schedinfo>> task_list;
    task_list.reserve(RUNNING_TASKS() + 64);
    for(ulong task_addr: for_each_threads()){
        struct task_context *tc = task_to_context(task_addr);
        if(!tc || tc->processor != cpu){
            continue;
        }
        std::shared_ptr<schedinfo> sched_ptr = std::make_shared<schedinfo>();
        sched_ptr->tc = tc;
        sched_ptr->task_prio = read_uint(task_addr + off_prio, "prio");
        sched_ptr->policy = read_uint(task_addr + off_policy, "policy");
        const bool fair_policy = sched_ptr->policy == 0 ||
                                 sched_ptr->policy == 3 ||
                                 sched_ptr->policy == 5;
        const bool rt_policy = sched_ptr->policy == 1 || sched_ptr->policy == 2;
        if (has_sched_info) {
            sched_ptr->last_arrival = read_ulonglong(task_addr + off_sched_info + off_last_arrival, "last_arrival");
            sched_ptr->last_queued = read_ulonglong(task_addr + off_sched_info + off_last_queued, "last_queued");
            sched_ptr->pcount = read_uint(task_addr + off_sched_info + off_pcount, "pcount");
            sched_ptr->run_delay = read_ulonglong(task_addr + off_sched_info + off_run_delay, "run_delay");
        }
        if(off_last_enq_ts != -1){
            sched_ptr->last_enqueued = read_ulonglong(task_addr + off_last_enq_ts, "last_enqueued_ts");
        } else {
            if (is_walt) {
                if (off_wts >= 0) {
                    sched_ptr->last_enqueued = read_ulonglong(task_addr + off_wts + off_walt_enq, "last_enqueued_ts");
                } else if (off_avd1 >= 0) {
                    sched_ptr->last_enqueued = read_ulonglong(task_addr + off_avd1 + off_walt_enq, "last_enqueued_ts");
                }
            }
        }
        if(off_last_sleep_ts != -1){
            sched_ptr->last_sleep = read_ulonglong(task_addr + off_last_sleep_ts, "last_sleep_ts");
        } else {
            if (is_walt) {
                if (off_wts >= 0) {
                    sched_ptr->last_sleep = read_ulonglong(task_addr + off_wts + off_walt_sleep, "last_sleep_ts");
                } else if (off_avd1 >= 0) {
                    sched_ptr->last_sleep = read_ulonglong(task_addr + off_avd1 + off_walt_sleep, "last_sleep_ts");
                }
            }
        }
        if (sched_ptr->last_enqueued < sched_ptr->last_sleep){
            sched_ptr->runtime = sched_ptr->last_sleep - sched_ptr->last_enqueued;
        }

        if (fair_policy && has_cfs_bw) {
            ulong cfs_rq_addr = read_pointer(task_addr + off_task_se + off_se_cfs_rq, "se.cfs_rq");
            if (is_kvaddr(cfs_rq_addr)) {
                int64_t runtime_remaining = 0;
                if (read_struct(cfs_rq_addr + off_cfs_runtime_remaining,
                                &runtime_remaining, sizeof(runtime_remaining),
                                "cfs_rq.runtime_remaining")) {
                    sched_ptr->has_cfs_bw = true;
                    sched_ptr->cfs_throttled = read_int(cfs_rq_addr + off_cfs_throttled, "cfs_rq.throttled");
                    sched_ptr->cfs_runtime_remaining = runtime_remaining;
                    sched_ptr->cfs_throttle_count = read_int(cfs_rq_addr + off_cfs_throttle_count, "cfs_rq.throttle_count");
                }
            }
        }

        if (rt_policy && has_rt_bw) {
            ulong rt_rq_addr = read_pointer(task_addr + off_task_rt + off_rt_rt_rq, "rt.rt_rq");
            if (is_kvaddr(rt_rq_addr)) {
                sched_ptr->has_rt_bw = true;
                sched_ptr->rt_throttled = read_int(rt_rq_addr + off_rt_throttled, "rt_rq.rt_throttled");
                sched_ptr->rt_time = read_ulonglong(rt_rq_addr + off_rt_time, "rt_rq.rt_time");
                sched_ptr->rt_runtime = read_ulonglong(rt_rq_addr + off_rt_runtime, "rt_rq.rt_runtime");
            }
        }
        task_list.push_back(sched_ptr);
    }
    if (task_list.size() == 0){
        PRINT("No tasks found on cpu %d\n", cpu);
        return;
    }
    auto throttle_rank_label = [](const std::shared_ptr<schedinfo>& s) -> std::pair<int, std::string> {
        if (s->rt_throttled == 1) {
            return {0, "RT"};
        }
        if (s->cfs_throttled == 1) {
            return {1, "CFS_SELF"};
        }
        if (s->cfs_throttle_count > 0) {
            return {2, "CFS_ANCESTOR"};
        }
        if (s->has_rt_bw || s->has_cfs_bw ||
            s->policy == 1 || s->policy == 2 || s->policy == 0 ||
            s->policy == 3 || s->policy == 5) {
            return {3, "No"};
        }
        return {4, "N/A"};
    };
    std::sort(task_list.begin(), task_list.end(),
              [&](const std::shared_ptr<schedinfo>& a, const std::shared_ptr<schedinfo>& b) {
                  const int ra = throttle_rank_label(a).first;
                  const int rb = throttle_rank_label(b).first;
                  if (ra != rb) {
                      return ra < rb;
                  }
                  return a->last_arrival < b->last_arrival;
              });
    auto policy_to_string = [](uint32_t policy) -> std::string {
        switch (policy) {
            case 0: return "CFS";
            case 1: return "FIFO";
            case 2: return "RR";
            case 3: return "BATCH";
            case 5: return "IDLE";
            case 6: return "DL";
            default: return std::to_string(policy);
        }
    };

    const std::vector<std::string> headers = {
        "Name", "pid", "cpu", "Exec_Started", "Last_Queued", "Total_wait_time",
        "times_exec", "Prio", "Policy", "State", "Last_enqueued_ts", "Last_sleep_ts", "Last_runtime",
        "Throttle", "BudgetLeft(ms)", "ThrotCnt"
    };
    std::vector<std::vector<std::string>> rows;
    rows.reserve(task_list.size());
    size_t cfs_throttled_tasks = 0;
    size_t rt_throttled_tasks = 0;

    for (const auto& sched_ptr : task_list) {
        char buf2[BUFSIZE];
        const std::string policy = policy_to_string(sched_ptr->policy);
        const auto rank_label = throttle_rank_label(sched_ptr);
        std::string throttle = rank_label.second;
        std::string budget_left = "-";
        std::string throttle_cnt = "-";

        if (rank_label.first == 0) {
            rt_throttled_tasks++;
        } else if (rank_label.first == 1) {
            cfs_throttled_tasks++;
        }

        if (sched_ptr->has_rt_bw) {
            if (sched_ptr->rt_runtime == std::numeric_limits<uint64_t>::max()) {
                budget_left = "UNLIMITED";
            } else {
                budget_left = format_ns_value(
                    static_cast<long double>(static_cast<int64_t>(sched_ptr->rt_runtime) - static_cast<int64_t>(sched_ptr->rt_time)),
                    TimeUnit::MS);
            }
        } else if (sched_ptr->has_cfs_bw) {
            budget_left = format_ns_value(static_cast<long double>(sched_ptr->cfs_runtime_remaining), TimeUnit::MS);
            throttle_cnt = std::to_string(sched_ptr->cfs_throttle_count);
        }

        rows.push_back({
            sched_ptr->tc->comm,
            std::to_string(sched_ptr->tc->pid),
            task_cpu(sched_ptr->tc->processor, buf2, !VERBOSE),
            format_ns_value(static_cast<long double>(sched_ptr->last_arrival), TimeUnit::SEC),
            format_ns_value(static_cast<long double>(sched_ptr->last_queued), TimeUnit::SEC),
            format_ns_value(static_cast<long double>(sched_ptr->run_delay), TimeUnit::SEC),
            std::to_string(sched_ptr->pcount),
            std::to_string(sched_ptr->task_prio),
            policy,
            task_state_display(sched_ptr->tc->task),
            format_ns_value(static_cast<long double>(sched_ptr->last_enqueued), TimeUnit::SEC),
            format_ns_value(static_cast<long double>(sched_ptr->last_sleep), TimeUnit::SEC),
            format_ns_value(static_cast<long double>(sched_ptr->runtime), TimeUnit::SEC),
            throttle,
            budget_left,
            throttle_cnt,
        });
    }

    const std::vector<bool> align = {
        false, true, true, true, true, true, true, true, false, false, true, true, true, false, true, true
    };
    std::ostringstream title;
    title << "SCHED TASK INFO (CPU " << cpu << ")";
    std::ostringstream footer;
    footer << "Total Tasks: " << task_list.size()
           << " | CFS throttled: " << cfs_throttled_tasks
           << " | RT throttled: " << rt_throttled_tasks;
    const std::string table = build_box_table(title.str(), headers, rows, align, footer.str());
    PRINT("%s \n", table.c_str());
    print_throttle_overview(cpu, false);
}

void TaskSched::print_throttle_overview(int cpu, bool detail) {
    if (!csymbol_exists("runqueues")) {
        PRINT("runqueues symbol not found in this kernel.\n");
        return;
    }

    const ulong runqueues_addr = csymbol_value("runqueues");
    std::vector<ulong> rq_list = for_each_percpu(runqueues_addr);
    if (rq_list.empty()) {
        PRINT("No per-cpu runqueue found.\n");
        return;
    }

    int off_rq_nr_running = field_offset(rq, nr_running);
    int off_rq_cfs = field_offset(rq, cfs);
    int off_rq_rt = field_offset(rq, rt);
    if (off_rq_nr_running == -1 || off_rq_cfs == -1 || off_rq_rt == -1) {
        off_rq_nr_running = field_offset(runqueue, nr_running);
        off_rq_cfs = field_offset(runqueue, cfs);
        off_rq_rt = field_offset(runqueue, rt);
    }
    if (off_rq_nr_running == -1 || off_rq_cfs == -1 || off_rq_rt == -1) {
        PRINT("rq/runqueue layout unsupported for throttle view in this kernel.\n");
        return;
    }

    const int off_tg_list = field_offset(task_group, list);
    const int off_tg_cfs_rq = field_offset(task_group, cfs_rq);
    const int off_tg_rt_rq = field_offset(task_group, rt_rq);
    const int off_tg_cfs_bw = field_offset(task_group, cfs_bandwidth);
    const int off_tg_rt_bw = field_offset(task_group, rt_bandwidth);
    const int off_tg_css = field_offset(task_group, css);

    const int off_css_cgroup = field_offset(cgroup_subsys_state, cgroup);
    const int off_cgrp_kn = field_offset(cgroup, kn);
    const int off_kn_parent = field_offset(kernfs_node, parent);
    const int off_kn_name = field_offset(kernfs_node, name);

    const int off_cfs_throttled = field_offset(cfs_rq, throttled);
    const int off_cfs_runtime_remaining = field_offset(cfs_rq, runtime_remaining);
    const int off_cfs_throttle_count = field_offset(cfs_rq, throttle_count);
    const int off_cfs_nr_running = field_offset(cfs_rq, nr_running);
    const int off_cfs_tg = field_offset(cfs_rq, tg);

    const int off_rt_throttled = field_offset(rt_rq, rt_throttled);
    const int off_rt_time = field_offset(rt_rq, rt_time);
    const int off_rt_runtime = field_offset(rt_rq, rt_runtime);
    const int off_rt_nr_boosted = field_offset(rt_rq, rt_nr_boosted);
    const int off_rt_tg = field_offset(rt_rq, tg);

    const int off_bw_period = field_offset(cfs_bandwidth, period);
    const int off_bw_quota = field_offset(cfs_bandwidth, quota);
    const int off_bw_period_active = field_offset(cfs_bandwidth, period_active);
    const int off_bw_nr_periods = field_offset(cfs_bandwidth, nr_periods);
    const int off_bw_nr_throttled = field_offset(cfs_bandwidth, nr_throttled);
    const int off_bw_throttled_time = field_offset(cfs_bandwidth, throttled_time);
    const int off_bw_period_timer = field_offset(cfs_bandwidth, period_timer);

    const int off_rtb_period = field_offset(rt_bandwidth, rt_period);
    const int off_rtb_period_active = field_offset(rt_bandwidth, rt_period_active);
    const int off_rtb_period_timer = field_offset(rt_bandwidth, rt_period_timer);

    const int off_hr_node = field_offset(hrtimer, node);
    const int off_hr_fn = field_offset(hrtimer, function);
    const int off_hr_base = field_offset(hrtimer, base);
    const int off_hr_state = field_offset(hrtimer, state);
    const int off_hr_soft = field_offset(hrtimer, is_soft);
    const int off_hr_hard = field_offset(hrtimer, is_hard);
    const int off_tq_expires = field_offset(timerqueue_node, expires);
    const int off_task_se = field_offset(task_struct, se);
    const int off_se_cfs_rq = field_offset(sched_entity, cfs_rq);
    const int off_task_rt = field_offset(task_struct, rt);
    const int off_rt_rt_rq = field_offset(sched_rt_entity, rt_rq);

    const bool rt_group_sched = get_config_val("CONFIG_RT_GROUP_SCHED") == "y";
    const bool has_timer_layout = off_hr_node >= 0 && off_hr_fn >= 0 &&
                                  off_hr_base >= 0 && off_hr_state >= 0 &&
                                  off_tq_expires >= 0;
    const bool has_cfs_bw = get_config_val("CONFIG_CFS_BANDWIDTH") == "y" &&
                            get_config_val("CONFIG_FAIR_GROUP_SCHED") == "y" &&
                            off_tg_list >= 0 && off_tg_cfs_rq >= 0 &&
                            off_tg_cfs_bw >= 0 && off_cfs_throttled >= 0 &&
                            off_cfs_runtime_remaining >= 0 &&
                            off_cfs_throttle_count >= 0 &&
                            off_cfs_nr_running >= 0 && off_cfs_tg >= 0 &&
                            off_bw_period >= 0 && off_bw_quota >= 0 &&
                            off_bw_period_active >= 0 && off_bw_nr_periods >= 0 &&
                            off_bw_nr_throttled >= 0 &&
                            off_bw_throttled_time >= 0 && off_bw_period_timer >= 0;
    const bool has_rt_group_layout = rt_group_sched &&
                                     off_tg_list >= 0 && off_tg_rt_rq >= 0 &&
                                     off_tg_rt_bw >= 0 && off_rt_nr_boosted >= 0 &&
                                     off_rt_tg >= 0;
    const bool has_rt_bw = off_rt_throttled >= 0 && off_rt_time >= 0 &&
                           off_rt_runtime >= 0 && off_rtb_period >= 0 &&
                           off_rtb_period_active >= 0 && off_rtb_period_timer >= 0 &&
                           (!rt_group_sched || has_rt_group_layout);
    const bool has_tg_path = off_tg_css >= 0 && off_css_cgroup >= 0 &&
                             off_cgrp_kn >= 0 && off_kn_parent >= 0 &&
                             off_kn_name >= 0;
    if (!has_cfs_bw && !has_rt_bw) {
        PRINT("CFS/RT bandwidth layout unavailable in this kernel configuration.\n");
        return;
    }

    struct TimerRead {
        bool valid;
        bool armed;
        bool fn_ok;
        int64_t expires_ns;
        std::string expires_ns_str;
        std::string fn_ok_str;
        std::string state_str;
        std::string base_str;
        std::string soft_irq_str;
        std::string hard_irq_str;
    };
    auto read_timer = [&](ulong timer_addr, ulong expected_fn, const std::string& prefix) -> TimerRead {
        if (!has_timer_layout) {
            return {false, false, false, 0, "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"};
        }
        const uint32_t state = read_byte(timer_addr + off_hr_state, prefix + ".state");
        const ulong fn = read_pointer(timer_addr + off_hr_fn, prefix + ".function");
        int64_t expires = 0;
        if (!read_struct(timer_addr + off_hr_node + off_tq_expires,
                         &expires, sizeof(expires), prefix + ".node.expires")) {
            return {false, false, false, 0, "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"};
        }
        char base_buf[32] = {0};
        snprintf(base_buf, sizeof(base_buf), "%#lx", read_pointer(timer_addr + off_hr_base, prefix + ".base"));
        return {
            true,
            ((state & 0x1U) != 0),
            (expected_fn == 0) ? true : (fn == expected_fn),
            expires,
            std::to_string(expires),
            (expected_fn == 0) ? "N/A" : ((fn == expected_fn) ? "Yes" : "No"),
            std::to_string(state),
            std::string(base_buf),
            off_hr_soft >= 0 ? std::to_string(read_byte(timer_addr + off_hr_soft, prefix + ".is_soft")) : "N/A",
            off_hr_hard >= 0 ? std::to_string(read_byte(timer_addr + off_hr_hard, prefix + ".is_hard")) : "N/A"
        };
    };
    std::map<ulong, std::string> tg_path_cache;
    auto tg_path_of = [&](ulong tg_addr) -> std::string {
        if (!is_kvaddr(tg_addr) || !has_tg_path) {
            return "N/A";
        }
        auto it = tg_path_cache.find(tg_addr);
        if (it != tg_path_cache.end()) {
            return it->second;
        }

        ulong css_addr = tg_addr + off_tg_css;
        ulong cgrp_addr = read_pointer(css_addr + off_css_cgroup, "tg.css.cgroup");
        ulong kn_addr = is_kvaddr(cgrp_addr) ? read_pointer(cgrp_addr + off_cgrp_kn, "cgroup.kn") : 0;

        std::vector<std::string> names;
        while (is_kvaddr(kn_addr)) {
            ulong name_ptr = read_pointer(kn_addr + off_kn_name, "kernfs_node.name");
            std::string name = is_kvaddr(name_ptr) ? read_cstring(name_ptr, 128, "kernfs_node.name.str") : "";
            if (!name.empty()) {
                names.push_back(name);
            }
            kn_addr = read_pointer(kn_addr + off_kn_parent, "kernfs_node.parent");
        }

        std::string path = "/";
        for (auto rit = names.rbegin(); rit != names.rend(); ++rit) {
            if (rit->empty()) {
                continue;
            }
            if (path.size() > 1) {
                path += "/";
            }
            path += *rit;
        }
        tg_path_cache[tg_addr] = path;
        return path;
    };

    std::vector<int> cpus;
    if (cpu >= 0) {
        if (cpu >= static_cast<int>(rq_list.size()) || !is_kvaddr(rq_list[cpu])) {
            PRINT("Invalid CPU %d or runqueue is unavailable.\n", cpu);
            return;
        }
        cpus.push_back(cpu);
    } else {
        cpus.reserve(rq_list.size());
        for (size_t i = 0; i < rq_list.size(); ++i) {
            if (is_kvaddr(rq_list[i])) {
                cpus.push_back(static_cast<int>(i));
            }
        }
    }
    if (cpus.empty()) {
        PRINT("No online CPU runqueue found.\n");
        return;
    }

    const ulong cfs_period_fn = csymbol_exists("sched_cfs_period_timer") ? csymbol_value("sched_cfs_period_timer") : 0;
    const ulong rt_period_fn = csymbol_exists("sched_rt_period_timer") ? csymbol_value("sched_rt_period_timer") : 0;
    const ulong def_rt_bw = csymbol_exists("def_rt_bandwidth") ? csymbol_value("def_rt_bandwidth") : 0;

    std::set<int> cpu_set(cpus.begin(), cpus.end());
    std::map<int, std::set<ulong>> cpu_cfs_rq_map;
    std::map<int, std::set<ulong>> cpu_rt_rq_map;

    const bool has_task_cfs_rq = off_task_se >= 0 && off_se_cfs_rq >= 0;
    const bool has_task_rt_rq = has_rt_group_layout &&
                                off_task_rt >= 0 && off_rt_rt_rq >= 0;
    if (csymbol_exists("task_groups") &&
        (has_cfs_bw || has_rt_group_layout)) {
        ulong tgs = csymbol_value("task_groups");
        for (ulong tg_addr : for_each_list(tgs, off_tg_list)) {
            if (has_cfs_bw) {
                ulong cfs_arr = read_pointer(tg_addr + off_tg_cfs_rq, "task_group.cfs_rq");
                if (is_kvaddr(cfs_arr)) {
                    for (int cid : cpus) {
                        ulong cfs_rq_addr = read_pointer(cfs_arr + static_cast<ulong>(cid) * sizeof(ulong), "tg->cfs_rq[cpu]");
                        if (is_kvaddr(cfs_rq_addr)) {
                            cpu_cfs_rq_map[cid].insert(cfs_rq_addr);
                        }
                    }
                }
            }
            if (has_rt_group_layout) {
                ulong rt_arr = read_pointer(tg_addr + off_tg_rt_rq, "task_group.rt_rq");
                if (is_kvaddr(rt_arr)) {
                    for (int cid : cpus) {
                        ulong rt_rq_addr = read_pointer(rt_arr + static_cast<ulong>(cid) * sizeof(ulong), "tg->rt_rq[cpu]");
                        if (is_kvaddr(rt_rq_addr)) {
                            cpu_rt_rq_map[cid].insert(rt_rq_addr);
                        }
                    }
                }
            }
        }
    } else {
        for (ulong task_addr : for_each_threads()) {
            struct task_context *tc = task_to_context(task_addr);
            if (!tc || cpu_set.find(tc->processor) == cpu_set.end()) {
                continue;
            }
            if (has_cfs_bw && has_task_cfs_rq) {
                ulong cfs_rq_addr = read_pointer(task_addr + off_task_se + off_se_cfs_rq, "se.cfs_rq");
                if (is_kvaddr(cfs_rq_addr)) {
                    cpu_cfs_rq_map[tc->processor].insert(cfs_rq_addr);
                }
            }
            if (has_task_rt_rq) {
                ulong rt_rq_addr = read_pointer(task_addr + off_task_rt + off_rt_rt_rq, "rt.rt_rq");
                if (is_kvaddr(rt_rq_addr)) {
                    cpu_rt_rq_map[tc->processor].insert(rt_rq_addr);
                }
            }
        }
    }

    for (int cid : cpus) {
        const ulong rq_addr = rq_list[cid];
        if (has_cfs_bw) {
            cpu_cfs_rq_map[cid].insert(rq_addr + off_rq_cfs);
        }
        if (has_rt_bw) {
            cpu_rt_rq_map[cid].insert(rq_addr + off_rq_rt);
        }
    }

    struct SummaryRow {
        int limited_rank;
        int cpu;
        std::vector<std::string> row;
    };
    std::vector<SummaryRow> summary_detail_rows;
    std::vector<std::vector<std::string>> summary_rows;
    summary_detail_rows.reserve(cpus.size());

    for (int cid : cpus) {
        bool cfs_limited = false;
        int cfs_self = 0;
        int cfs_ancestor = 0;
        bool cfs_timer_armed = false;
        bool cfs_timer_fn_ok = false;
        bool cfs_timer_seen = false;
        int64_t cfs_next_exp = 0;

        for (ulong cfs_rq_addr : cpu_cfs_rq_map[cid]) {
            const int throttled = read_int(cfs_rq_addr + off_cfs_throttled, "cfs_rq.throttled");
            const int cnt = read_int(cfs_rq_addr + off_cfs_throttle_count, "cfs_rq.throttle_count");
            const bool limited = (throttled == 1 || cnt > 0);
            if (!limited) {
                continue;
            }
            cfs_limited = true;
            if (throttled == 1) cfs_self++;
            else cfs_ancestor++;

            ulong tg_addr = read_pointer(cfs_rq_addr + off_cfs_tg, "cfs_rq.tg");
            if (!is_kvaddr(tg_addr)) {
                continue;
            }
            if (has_timer_layout) {
                ulong bw_addr = tg_addr + off_tg_cfs_bw;
                ulong timer_addr = bw_addr + off_bw_period_timer;
                const auto timer = read_timer(timer_addr, cfs_period_fn, "cfs.period_timer");
                if (!timer.valid) {
                    continue;
                }
                cfs_timer_seen = true;
                cfs_timer_armed = cfs_timer_armed || timer.armed;
                if (cfs_period_fn != 0) {
                    cfs_timer_fn_ok = cfs_timer_fn_ok || timer.fn_ok;
                }
                if (cfs_next_exp == 0 || timer.expires_ns < cfs_next_exp) {
                    cfs_next_exp = timer.expires_ns;
                }
            }
        }

        bool rt_limited = false;
        bool rt_timer_armed = false;
        bool rt_timer_fn_ok = false;
        bool rt_timer_seen = false;
        int64_t rt_next_exp = 0;

        for (ulong rt_rq_addr : cpu_rt_rq_map[cid]) {
            const int throttled = read_int(rt_rq_addr + off_rt_throttled, "rt_rq.rt_throttled");
            const uint32_t boosted = has_rt_group_layout
                                         ? read_uint(rt_rq_addr + off_rt_nr_boosted, "rt_rq.rt_nr_boosted")
                                         : 0;
            const bool effective = has_rt_group_layout
                                       ? (throttled == 1 && boosted == 0)
                                       : (throttled == 1);
            if (!effective) {
                continue;
            }
            rt_limited = true;

            ulong bw_addr = 0;
            if (has_rt_group_layout) {
                ulong tg_addr = read_pointer(rt_rq_addr + off_rt_tg, "rt_rq.tg");
                if (is_kvaddr(tg_addr)) {
                    bw_addr = tg_addr + off_tg_rt_bw;
                }
            } else if (is_kvaddr(def_rt_bw)) {
                bw_addr = def_rt_bw;
            }
            if (!has_timer_layout || !is_kvaddr(bw_addr)) {
                continue;
            }
            ulong timer_addr = bw_addr + off_rtb_period_timer;
            const auto timer = read_timer(timer_addr, rt_period_fn, "rt.period_timer");
            if (!timer.valid) {
                continue;
            }
            rt_timer_seen = true;
            rt_timer_armed = rt_timer_armed || timer.armed;
            if (rt_period_fn != 0) {
                rt_timer_fn_ok = rt_timer_fn_ok || timer.fn_ok;
            }
            if (rt_next_exp == 0 || timer.expires_ns < rt_next_exp) {
                rt_next_exp = timer.expires_ns;
            }
        }

        std::string anomaly = "-";
        if (has_timer_layout && cfs_limited &&
            (!cfs_timer_seen || !cfs_timer_armed ||
             (cfs_period_fn != 0 && !cfs_timer_fn_ok))) {
            anomaly = "CFS_TIMER";
        }
        if (has_timer_layout && rt_limited &&
            (!rt_timer_seen || !rt_timer_armed ||
             (rt_period_fn != 0 && !rt_timer_fn_ok))) {
            anomaly = (anomaly == "-") ? "RT_TIMER" : "CFS_TIMER|RT_TIMER";
        }
        summary_detail_rows.push_back({
            (cfs_limited || rt_limited) ? 0 : 1,
            cid,
            {
                std::to_string(cid),
                has_cfs_bw ? (cfs_limited ? "Yes" : "No") : "N/A",
                has_cfs_bw ? std::to_string(cfs_self) : "N/A",
                has_cfs_bw ? std::to_string(cfs_ancestor) : "N/A",
                cfs_timer_seen ? (cfs_timer_armed ? "Yes" : "No") : "N/A",
                (cfs_period_fn != 0) ? (cfs_timer_seen ? (cfs_timer_fn_ok ? "Yes" : "No") : "N/A") : "N/A",
                (cfs_next_exp != 0) ? std::to_string(cfs_next_exp) : "N/A",
                has_rt_bw ? (rt_limited ? "Yes" : "No") : "N/A",
                rt_timer_seen ? (rt_timer_armed ? "Yes" : "No") : "N/A",
                (rt_period_fn != 0) ? (rt_timer_seen ? (rt_timer_fn_ok ? "Yes" : "No") : "N/A") : "N/A",
                (rt_next_exp != 0) ? std::to_string(rt_next_exp) : "N/A",
                anomaly
            }
        });
    }
    std::sort(summary_detail_rows.begin(), summary_detail_rows.end(),
              [](const SummaryRow& a, const SummaryRow& b) {
                  if (a.limited_rank != b.limited_rank) return a.limited_rank < b.limited_rank;
                  return a.cpu < b.cpu;
              });
    summary_rows.reserve(summary_detail_rows.size());
    for (const auto& e : summary_detail_rows) {
        summary_rows.push_back(e.row);
    }

    const bool show_summary = (!detail) || (cpu < 0);
    if (show_summary) {
        const std::vector<std::string> summary_headers = {
            "CPU", "CFS_limited", "CFS_self", "CFS_parent_throttled",
            "CFS_timer_armed", "CFS_timer_fn_ok", "CFS_next_exp(ns)",
            "RT_limited", "RT_timer_armed", "RT_timer_fn_ok", "RT_next_exp(ns)", "Potential_issue"
        };
        std::ostringstream title;
        if (detail) {
            title << "SCHED THROTTLE SUMMARY (" << ((cpu >= 0) ? ("CPU " + std::to_string(cpu)) : "ALL CPUS") << ")";
        } else {
            title << "SCHED THROTTLE SUMMARY (CPU " << cpu << ")";
        }
        PRINT("%s\n", build_box_table(
            title.str(),
            summary_headers,
            summary_rows,
            {true, false, true, true, false, false, true, false, false, false, true, false},
            std::string("CONFIG_RT_GROUP_SCHED=") + (rt_group_sched ? "y" : "n")
        ).c_str());
    }

    if (!detail) {
        return;
    }

    const std::vector<std::string> cfs_headers = {
        "CPU", "TG", "TG_PATH", "CFS_RQ", "State", "throttle_count", "runtime_left(ms)", "nr_running",
        "quota(ms)", "period(ms)", "nr_periods", "nr_throttled", "throttled_time(ms)", "period_active",
        "timer_expires(ns)", "timer_fn_ok", "timer_state", "timer_base", "is_soft_irq", "is_hard_irq"
    };
    struct CfsDetailRow {
        int state_rank;
        std::string tg_path;
        ulong tg_addr;
        int cpu;
        ulong cfs_rq_addr;
        std::vector<std::string> row;
    };
    std::vector<CfsDetailRow> cfs_detail_rows;
    std::vector<std::vector<std::string>> cfs_rows;
    size_t cfs_self_rows = 0;
    size_t cfs_ancestor_rows = 0;

    for (int cid : cpus) {
        for (ulong cfs_rq_addr : cpu_cfs_rq_map[cid]) {
            const int throttled = read_int(cfs_rq_addr + off_cfs_throttled, "cfs_rq.throttled");
            const int cnt = read_int(cfs_rq_addr + off_cfs_throttle_count, "cfs_rq.throttle_count");
            int64_t left = 0;
            const bool left_valid = read_struct(cfs_rq_addr + off_cfs_runtime_remaining,
                                                &left, sizeof(left),
                                                "cfs_rq.runtime_remaining");
            const uint32_t nr_running = read_uint(cfs_rq_addr + off_cfs_nr_running, "cfs_rq.nr_running");

            std::string state = "NOT_THROTTLED";
            if (throttled == 1) {
                state = "SELF_THROTTLED";
                cfs_self_rows++;
            } else if (cnt > 0) {
                state = "ANCESTOR_THROTTLED";
                cfs_ancestor_rows++;
            }

            ulong tg_addr = read_pointer(cfs_rq_addr + off_cfs_tg, "cfs_rq.tg");
            std::string quota = "N/A", period = "N/A", nr_periods = "N/A", nr_throttled = "N/A", throttled_time = "N/A";
            std::string period_active = "N/A", timer_exp = "N/A", timer_fn_ok = "N/A", timer_state = "N/A", timer_base = "N/A", timer_soft = "N/A", timer_hard = "N/A";
            std::string tg_path = tg_path_of(tg_addr);

            if (is_kvaddr(tg_addr)) {
                const ulong bw_addr = tg_addr + off_tg_cfs_bw;
                const uint64_t q = read_ulonglong(bw_addr + off_bw_quota, "cfs_bandwidth.quota");
                quota = (q == UINT64_MAX) ? "UNLIMITED" : format_ns_value(static_cast<long double>(q), TimeUnit::MS);
                int64_t period_ns = 0;
                if (read_struct(bw_addr + off_bw_period, &period_ns,
                                sizeof(period_ns), "cfs_bandwidth.period")) {
                    period = format_ns_value(static_cast<long double>(period_ns), TimeUnit::MS);
                }
                nr_periods = std::to_string(read_int(bw_addr + off_bw_nr_periods, "cfs_bandwidth.nr_periods"));
                nr_throttled = std::to_string(read_int(bw_addr + off_bw_nr_throttled, "cfs_bandwidth.nr_throttled"));
                throttled_time = format_ns_value(static_cast<long double>(read_ulonglong(bw_addr + off_bw_throttled_time, "cfs_bandwidth.throttled_time")), TimeUnit::MS);
                period_active = std::to_string(read_byte(bw_addr + off_bw_period_active, "cfs_bandwidth.period_active"));

                const ulong t = bw_addr + off_bw_period_timer;
                const auto timer = read_timer(t, cfs_period_fn, "period_timer");
                timer_exp = timer.expires_ns_str;
                timer_fn_ok = timer.fn_ok_str;
                timer_state = timer.state_str;
                timer_base = timer.base_str;
                timer_soft = timer.soft_irq_str;
                timer_hard = timer.hard_irq_str;
            }

            if (state == "NOT_THROTTLED" && nr_running == 0 && period_active != "1") {
                continue;
            }

            int state_rank = 2;
            if (state == "SELF_THROTTLED") {
                state_rank = 0;
            } else if (state == "ANCESTOR_THROTTLED") {
                state_rank = 1;
            }
            std::string tg_hex = "N/A";
            if (is_kvaddr(tg_addr)) {
                char tg_buf[32] = {0};
                snprintf(tg_buf, sizeof(tg_buf), "%#lx", tg_addr);
                tg_hex = tg_buf;
            }
            char cfs_buf[32] = {0};
            snprintf(cfs_buf, sizeof(cfs_buf), "%#lx", cfs_rq_addr);
            cfs_detail_rows.push_back({
                state_rank,
                tg_path,
                tg_addr,
                cid,
                cfs_rq_addr,
                {
                    std::to_string(cid),
                    tg_hex,
                    tg_path,
                    cfs_buf,
                    state,
                    std::to_string(cnt),
                    left_valid ? format_ns_value(static_cast<long double>(left), TimeUnit::MS) : "N/A",
                    std::to_string(nr_running),
                    quota, period, nr_periods, nr_throttled, throttled_time, period_active,
                    timer_exp, timer_fn_ok, timer_state, timer_base, timer_soft, timer_hard
                }
            });
        }
    }
    std::sort(cfs_detail_rows.begin(), cfs_detail_rows.end(),
              [](const CfsDetailRow& a, const CfsDetailRow& b) {
                  if (a.state_rank != b.state_rank) return a.state_rank < b.state_rank;
                  if (a.tg_path != b.tg_path) return a.tg_path < b.tg_path;
                  if (a.tg_addr != b.tg_addr) return a.tg_addr < b.tg_addr;
                  if (a.cpu != b.cpu) return a.cpu < b.cpu;
                  return a.cfs_rq_addr < b.cfs_rq_addr;
              });
    cfs_rows.reserve(cfs_detail_rows.size());
    for (const auto& e : cfs_detail_rows) {
        cfs_rows.push_back(e.row);
    }

    PRINT("%s\n", build_box_table(
        "SCHED THROTTLE CFS DETAIL",
        cfs_headers,
        cfs_rows,
        {true, false, false, false, false, true, true, true, true, true, true, true, true, true, true, false, true, false, true, true},
        "rows: " + std::to_string(cfs_rows.size()) +
        " | SELF_THROTTLED: " + std::to_string(cfs_self_rows) +
        " | ANCESTOR_THROTTLED: " + std::to_string(cfs_ancestor_rows)
    ).c_str());

    const std::vector<std::string> rt_headers = {
        "CPU", "Scope", "TG", "TG_PATH", "RT_RQ", "effective_throttled", "rt_throttled", "rt_nr_boosted",
        "rt_used(ms)", "rt_runtime(ms)", "rt_left(ms)", "rt_period(ms)", "rt_period_active",
        "timer_expires(ns)", "timer_fn_ok", "timer_state", "timer_base", "is_soft_irq", "is_hard_irq"
    };
    struct RtDetailRow {
        int throttle_rank;
        std::string tg_path;
        ulong tg_addr;
        int cpu;
        ulong rt_rq_addr;
        std::vector<std::string> row;
    };
    std::vector<RtDetailRow> rt_detail_rows;
    std::vector<std::vector<std::string>> rt_rows;
    size_t rt_effective_rows = 0;

    for (int cid : cpus) {
        const ulong root_rt = rq_list[cid] + off_rq_rt;
        for (ulong rt_rq_addr : cpu_rt_rq_map[cid]) {
            const int throttled = read_int(rt_rq_addr + off_rt_throttled, "rt_rq.rt_throttled");
            const uint32_t boosted = has_rt_group_layout
                                         ? read_uint(rt_rq_addr + off_rt_nr_boosted, "rt_rq.rt_nr_boosted")
                                         : 0;
            const bool effective = has_rt_group_layout
                                       ? (throttled == 1 && boosted == 0)
                                       : (throttled == 1);
            const uint64_t used_ns = read_ulonglong(rt_rq_addr + off_rt_time, "rt_rq.rt_time");
            const uint64_t runtime_ns = read_ulonglong(rt_rq_addr + off_rt_runtime, "rt_rq.rt_runtime");

            ulong tg_addr = has_rt_group_layout
                                ? read_pointer(rt_rq_addr + off_rt_tg, "rt_rq.tg")
                                : 0;
            std::string tg_path = tg_path_of(tg_addr);
            ulong bw_addr = 0;
            if (has_rt_group_layout && is_kvaddr(tg_addr)) {
                bw_addr = tg_addr + off_tg_rt_bw;
            } else if (is_kvaddr(def_rt_bw)) {
                bw_addr = def_rt_bw;
            }

            std::string rt_period = "N/A", rt_period_active = "N/A", timer_exp = "N/A", timer_fn_ok = "N/A",
                        timer_state = "N/A", timer_base = "N/A", timer_soft = "N/A", timer_hard = "N/A";
            if (is_kvaddr(bw_addr)) {
                int64_t period_ns = 0;
                if (read_struct(bw_addr + off_rtb_period, &period_ns,
                                sizeof(period_ns), "rt_bandwidth.rt_period")) {
                    rt_period = format_ns_value(static_cast<long double>(period_ns), TimeUnit::MS);
                }
                rt_period_active = std::to_string(read_int(bw_addr + off_rtb_period_active, "rt_bandwidth.rt_period_active"));

                const ulong t = bw_addr + off_rtb_period_timer;
                const auto timer = read_timer(t, rt_period_fn, "rt_period_timer");
                timer_exp = timer.expires_ns_str;
                timer_fn_ok = timer.fn_ok_str;
                timer_state = timer.state_str;
                timer_base = timer.base_str;
                timer_soft = timer.soft_irq_str;
                timer_hard = timer.hard_irq_str;
            }

            if (!effective && used_ns == 0 && runtime_ns == 0 && rt_period_active != "1") {
                continue;
            }
            if (effective) rt_effective_rows++;

            std::string rt_runtime = "UNLIMITED";
            std::string rt_left = "UNLIMITED";
            if (runtime_ns != std::numeric_limits<uint64_t>::max()) {
                rt_runtime = format_ns_value(static_cast<long double>(runtime_ns), TimeUnit::MS);
                rt_left = format_ns_value(static_cast<long double>(static_cast<int64_t>(runtime_ns) - static_cast<int64_t>(used_ns)), TimeUnit::MS);
            }
            std::string tg_hex = "N/A";
            if (is_kvaddr(tg_addr)) {
                char tg_buf[32] = {0};
                snprintf(tg_buf, sizeof(tg_buf), "%#lx", tg_addr);
                tg_hex = tg_buf;
            }
            char rt_buf[32] = {0};
            snprintf(rt_buf, sizeof(rt_buf), "%#lx", rt_rq_addr);

            rt_detail_rows.push_back({
                effective ? 0 : 1,
                tg_path,
                tg_addr,
                cid,
                rt_rq_addr,
                {
                    std::to_string(cid),
                    (rt_rq_addr == root_rt) ? (rt_group_sched ? "ROOT_RQ" : "ROOT_ONLY") : "GROUP",
                    tg_hex,
                    tg_path,
                    rt_buf,
                    effective ? "Yes" : "No",
                    std::to_string(throttled),
                    std::to_string(boosted),
                    format_ns_value(static_cast<long double>(used_ns), TimeUnit::MS),
                    rt_runtime,
                    rt_left,
                    rt_period,
                    rt_period_active,
                    timer_exp,
                    timer_fn_ok,
                    timer_state,
                    timer_base,
                    timer_soft,
                    timer_hard
                }
            });
        }
    }
    std::sort(rt_detail_rows.begin(), rt_detail_rows.end(),
              [](const RtDetailRow& a, const RtDetailRow& b) {
                  if (a.throttle_rank != b.throttle_rank) return a.throttle_rank < b.throttle_rank;
                  if (a.tg_path != b.tg_path) return a.tg_path < b.tg_path;
                  if (a.tg_addr != b.tg_addr) return a.tg_addr < b.tg_addr;
                  if (a.cpu != b.cpu) return a.cpu < b.cpu;
                  return a.rt_rq_addr < b.rt_rq_addr;
              });
    rt_rows.reserve(rt_detail_rows.size());
    for (const auto& e : rt_detail_rows) {
        rt_rows.push_back(e.row);
    }

    PRINT("%s\n", build_box_table(
        "SCHED THROTTLE RT DETAIL",
        rt_headers,
        rt_rows,
        {true, false, false, false, false, false, true, true, true, true, true, true, true, true, false, true, false, true, true},
        "rows: " + std::to_string(rt_rows.size()) +
        " | effective_throttled: " + std::to_string(rt_effective_rows)
    ).c_str());
}

#pragma GCC diagnostic pop
