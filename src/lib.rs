#![allow(incomplete_features)]
#![feature(adt_const_params)]

use std::cell::UnsafeCell;
use std::marker::ConstParamTy;
use std::sync::atomic::{AtomicUsize, Ordering};

pub fn pin_core(core: usize) {
    unsafe {
        let mut cpuset = [0u8; 64];
        cpuset[core / 8] |= 1 << (core % 8) as u8;
        assert!(libc::sched_setaffinity(0, cpuset.len(), cpuset.as_ptr() as *const _) != -1);
    }
}

pub fn rdtsc() -> usize {
    unsafe { std::arch::x86_64::_rdtsc() as usize }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ConstParamTy)]
pub enum BenchType {
    /// Perform 4k mmap(), write one byte to the mapping, unmap the memory
    MmapWriteMunmap,

    /// Perform 4k mmap() with `MAP_POPULATE`, write one byte to the mapping,
    /// unmap the memory
    MmapWriteMunmapPopulate,

    /// Linearly map and touch a large chunk of memory (in KiB)
    LinearAlloc(usize),

    /// Linear alloc but with `MAP_POPULATE`
    LinearAllocPopulate(usize),
}

pub struct Statistics {
    pub job: AtomicUsize,
    pub threads: AtomicUsize,
    pub start_barrier: AtomicUsize,
    pub end_barrier: AtomicUsize,
    pub cum_time: AtomicUsize,
    pub cum_iters: AtomicUsize,
    pub bench_type: UnsafeCell<BenchType>,
}

pub fn bench(job_id: usize, core_id: usize, stats: &Statistics) {
    // Wait for job to be ready
    while stats.job.load(Ordering::Acquire) != job_id {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    let bench = unsafe { *stats.bench_type.get() };

    // Get the number of threads for this benchmark
    let threads = stats.threads.load(Ordering::Relaxed);
    if core_id >= threads {
        stats.end_barrier.fetch_add(1, Ordering::Release);
        return;
    }

    // Local iteration count
    let mut iters = 0;

    // Start barrier
    //
    // Wait for all threads to be fully alive and pinned to their
    // cores
    stats.start_barrier.fetch_add(1, Ordering::Relaxed);
    while stats.start_barrier.load(Ordering::Relaxed) != threads {}

    let it = rdtsc();

    match bench {
        BenchType::LinearAlloc(kib) | BenchType::LinearAllocPopulate(kib) => {
            for _ in 0..100 {
                unsafe {
                    let mmap = libc::mmap(
                        std::ptr::null_mut(),
                        kib * 1024,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_ANON
                            | libc::MAP_PRIVATE
                            | if matches!(bench, BenchType::LinearAllocPopulate(..)) {
                                libc::MAP_POPULATE
                            } else {
                                0
                            },
                        -1,
                        0,
                    );
                    assert!(mmap != libc::MAP_FAILED);

                    for ii in (0..kib * 1024).step_by(4096) {
                        core::ptr::write_volatile((mmap as *mut u8).add(ii), 4);
                    }

                    libc::munmap(mmap, kib * 1024);
                }

                iters += kib;
            }
        }
        _ => {
            for _ in 0..50 {
                unsafe {
                    let mmap = libc::mmap(
                        std::ptr::null_mut(),
                        4096,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_ANON
                            | libc::MAP_PRIVATE
                            | if bench == BenchType::MmapWriteMunmapPopulate {
                                libc::MAP_POPULATE
                            } else {
                                0
                            },
                        -1,
                        0,
                    );
                    assert!(mmap != libc::MAP_FAILED);

                    core::ptr::write_volatile(mmap as *mut u8, 4);

                    libc::munmap(mmap, 4096);
                }

                iters += 1;
            }
        }
    }
    let elapsed = rdtsc() - it;

    // Accumulate total cycle count of all cores
    stats.cum_iters.fetch_add(iters, Ordering::Relaxed);
    stats.cum_time.fetch_add(elapsed, Ordering::Relaxed);

    stats.end_barrier.fetch_add(1, Ordering::Release);
}

#[no_mangle]
extern "C" fn child(core_id: usize, stats: &Statistics) {
    // Pin to a specific core to avoid scheduler
    pin_core(core_id);

    for job_id in 1.. {
        bench(job_id, core_id, stats);
    }

    unsafe {
        libc::exit(0);
    }
}
