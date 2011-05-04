/*
 * Kernel-based Virtual Machine -- Performane Monitoring Unit support
 *
 * Copyright 2011 Red Hat, Inc. and/or its affiliates.
 *
 * Authors:
 *   Avi Kivity   <avi@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include <linux/types.h>
#include <linux/kvm_host.h>
#include <linux/perf_event.h>
#include "x86.h"
#include "pmu.h"
#include "lapic.h"

static struct kvm_arch_event_perf_mapping {
	u8 eventsel;
	u8 unit_mask;
	unsigned event_type;
	bool inexact;
} arch_events[] = {
	/* Index must match CPUID 0x0A.EBX bit vector */
	[0] = { 0x3c, 0x00, PERF_COUNT_HW_CPU_CYCLES },
	[1] = { 0xc0, 0x00, PERF_COUNT_HW_INSTRUCTIONS },
	[2] = { 0x3c, 0x01, PERF_COUNT_HW_BUS_CYCLES  },
	[3] = { 0x2e, 0x4f, PERF_COUNT_HW_CACHE_REFERENCES },
	[4] = { 0x2e, 0x41, PERF_COUNT_HW_CACHE_MISSES },
	[5] = { 0xc4, 0x00, PERF_COUNT_HW_BRANCH_INSTRUCTIONS },
	[6] = { 0xc5, 0x00, PERF_COUNT_HW_BRANCH_MISSES },
};

static inline struct kvm_pmc *get_gp_pmc(struct kvm_pmu *pmu, u32 msr,
					 u32 base)
{
	if (msr >= base && msr < base + pmu->nr_arch_gp_counters)
		return &pmu->gp_counters[msr - base];
	return NULL;
}

static void __kvm_perf_overflow(struct irq_work *irq_work)
{
	struct kvm_pmu *pmu = container_of(irq_work, struct kvm_pmu, irq_work);
	struct kvm_vcpu *vcpu = container_of(pmu, struct kvm_vcpu, arch.pmu);

	if (vcpu->arch.apic)
		kvm_apic_local_deliver(vcpu->arch.apic, APIC_LVTPC);
}

static void kvm_perf_overflow(struct perf_event *perf_event,
			      struct perf_sample_data *data,
			      struct pt_regs *regs)
{
	struct kvm_pmc *pmc = perf_event->overflow_handler_context;

	irq_work_queue(&pmc->vcpu->arch.pmu.irq_work);
}

static u64 read_gp_pmc(struct kvm_pmu *pmu, struct kvm_pmc *pmc)
{
	u64 counter, enabled, running;

	counter = pmc->counter;

	if (pmc->perf_event)
		counter += perf_event_read_value(pmc->perf_event,
						 &enabled, &running);

	/* FIXME: Scaling needed? */

	return counter & pmu->counter_bitmask;
}

static int reprogram_gp_counter(struct kvm_pmu *pmu, struct kvm_pmc *pmc,
				u64 eventsel)
{
	struct perf_event_attr attr = { };
	struct perf_event *event;
	int i;
	u8 event_select, unit_mask, cmask;
	perf_overflow_handler_t callback = NULL;
	bool inv;

	if (pmc->perf_event) {
		pmc->counter = read_gp_pmc(pmu, pmc);
		perf_event_release_kernel(pmc->perf_event);
		pmc->perf_event = NULL;
		irq_work_sync(&pmu->irq_work);
		pmc->eventsel = eventsel;
	}

	if (!(eventsel & ARCH_PERFMON_EVENTSEL_ENABLE))
		return 0;

	attr.type = PERF_TYPE_HARDWARE;
	attr.size = sizeof(attr);
	attr.exclude_idle = true;

	event_select = eventsel & ARCH_PERFMON_EVENTSEL_EVENT;
	unit_mask = (eventsel & ARCH_PERFMON_EVENTSEL_UMASK) >> 8;

	for (i = 0; i < ARRAY_SIZE(arch_events); ++i) {
		if (arch_events[i].eventsel == event_select
		    && arch_events[i].unit_mask == unit_mask
		    && (pmu->available_event_types & (1 << i))) {
			attr.config = arch_events[i].event_type;
			break;
		}
	}
	if (i == ARRAY_SIZE(arch_events))
		return 1;

	attr.exclude_user = !(eventsel & ARCH_PERFMON_EVENTSEL_USR);
	attr.exclude_kernel = !(eventsel & ARCH_PERFMON_EVENTSEL_OS);

	if (eventsel & ARCH_PERFMON_EVENTSEL_EDGE)
		printk_once("kvm: pmu ignoring edge bit\n");

	if (eventsel & ARCH_PERFMON_EVENTSEL_INT) {
		callback = kvm_perf_overflow;
		attr.disabled = true;
	}

	inv = eventsel & ARCH_PERFMON_EVENTSEL_INV;
	cmask = (eventsel & ARCH_PERFMON_EVENTSEL_CMASK) >> 24;

	pmc->eventsel = eventsel;

	if (inv || cmask > 1) {
		printk_once("kvm: pmu ignoring difficult inv/cmask combo\n");
		return 0;
	}

	attr.sample_period = (-pmc->counter) & pmu->counter_bitmask;

	event = perf_event_create_kernel_counter(&attr, -1, current,
						 callback, pmc);
	if (IS_ERR(event))
		return PTR_ERR(event);

	if (callback)
		perf_event_refresh(event, 1);

	pmc->perf_event = event;
	return 0;
}

bool kvm_pmu_msr(struct kvm_vcpu *vcpu, u32 msr)
{
	struct kvm_pmu *pmu = &vcpu->arch.pmu;

	return get_gp_pmc(pmu, msr, MSR_IA32_PERFCTR0)
		|| get_gp_pmc(pmu, msr, MSR_P6_EVNTSEL0);
}

int kvm_pmu_get_msr(struct kvm_vcpu *vcpu, u32 index, u64 *data)
{
	struct kvm_pmu *pmu = &vcpu->arch.pmu;
	struct kvm_pmc *pmc;

	if ((pmc = get_gp_pmc(pmu, index, MSR_IA32_PERFCTR0))) {
		*data = read_gp_pmc(pmu, pmc);
		return 0;
	} else if ((pmc = get_gp_pmc(pmu, index, MSR_P6_EVNTSEL0))) {
		*data = pmc->eventsel;
		return 0;
	}
	return 1;
}

int kvm_pmu_set_msr(struct kvm_vcpu *vcpu, u32 index, u64 data)
{
	struct kvm_pmu *pmu = &vcpu->arch.pmu;
	struct kvm_pmc *pmc;

	if ((pmc = get_gp_pmc(pmu, index, MSR_IA32_PERFCTR0))) {
		data = (s64)(s32)data;
		pmc->counter += data - read_gp_pmc(pmu, pmc);
		return 0;
	} else if ((pmc = get_gp_pmc(pmu, index, MSR_P6_EVNTSEL0))) {
		if (data == pmc->eventsel)
			return 0;
		if (data & 0xffffffff00200000ULL)
			return 1;
		return reprogram_gp_counter(pmu, pmc, data);
	}
	return 1;
}

int kvm_pmu_read_pmc(struct kvm_vcpu *vcpu, unsigned pmc, u64 *data)
{
	struct kvm_pmu *pmu = &vcpu->arch.pmu;
	bool fast_mode = pmc & (1u << 31);
	u64 ctr;

	pmc &= (1u << 31) - 1;
	if (pmc >= pmu->nr_arch_gp_counters)
		return 1;
	ctr = read_gp_pmc(pmu, &pmu->gp_counters[pmc]);
	if (fast_mode)
		ctr = (u32)ctr;
	*data = ctr;

	return 0;
}

void kvm_pmu_cpuid_update(struct kvm_vcpu *vcpu)
{
	struct kvm_pmu *pmu = &vcpu->arch.pmu;
	struct kvm_cpuid_entry2 *entry;
	unsigned bitmap_len;

	pmu->nr_arch_gp_counters = 0;
	pmu->version = 0;
	entry = kvm_find_cpuid_entry(vcpu, 0xa, 0);
	if (!entry)
		return;
	pmu->version = entry->eax & 0xff;
	pmu->nr_arch_gp_counters = min((int)(entry->eax >> 8) & 0xff,
				       KVM_PMU_MAX_GENERAL_PURPOSE_COUNTERS);
	pmu->counter_bitmask = ((u64)1 << ((entry->eax >> 16) & 0xff)) - 1;
	bitmap_len = (entry->eax >> 24) & 0xff;
	pmu->available_event_types = ~entry->ebx & ((1ULL << bitmap_len) - 1);
}

void kvm_pmu_init(struct kvm_vcpu *vcpu)
{
	int i;
	struct kvm_pmu *pmu = &vcpu->arch.pmu;

	memset(pmu, 0, sizeof(*pmu));
	for (i = 0; i < KVM_PMU_MAX_GENERAL_PURPOSE_COUNTERS; ++i)
		pmu->gp_counters[i].vcpu = vcpu;
	init_irq_work(&pmu->irq_work, __kvm_perf_overflow);
	kvm_pmu_cpuid_update(vcpu);
}

void kvm_pmu_destroy(struct kvm_vcpu *vcpu)
{
	struct kvm_pmu *pmu = &vcpu->arch.pmu;
	struct kvm_pmc *pmc;
	int i;

	irq_work_sync(&pmu->irq_work);
	for (i = 0; i < KVM_PMU_MAX_GENERAL_PURPOSE_COUNTERS; ++i) {
		pmc = &pmu->gp_counters[i];
		if (pmc->perf_event)
			perf_event_release_kernel(pmc->perf_event);
	}
}
