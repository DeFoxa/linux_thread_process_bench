#![allow(incomplete_features)]
#![feature(adt_const_params)]

use lib::*;
use std::sync::atomic::Ordering;

fn main() {
    // Create `/proc`
    // std::fs::create_dir_all("/proc").unwrap();

    // Mount procfs
    // unsafe {
    //     while libc::umount(c"/proc".as_ptr()) != -1 {}
    //     if libc::mount(c"proc".as_ptr(), c"/proc".as_ptr(),
    //                    c"proc".as_ptr(),
    //                    0, std::ptr::null_mut()) == -1 {
    //         panic!("{:?}", std::io::Error::last_os_error());
    //     }
    // }

    for clone_vm in [false, true] {
        for bench_type in [
            BenchType::MmapWriteMunmap,
            BenchType::MmapWriteMunmapPopulate,
            BenchType::LinearAlloc(256),
            BenchType::LinearAlloc(1024),
            BenchType::LinearAlloc(8192),
            BenchType::LinearAllocPopulate(256),
            BenchType::LinearAllocPopulate(1024),
            BenchType::LinearAllocPopulate(8192),
            BenchType::LinearAlloc(256),
            BenchType::LinearAlloc(512),
            BenchType::LinearAlloc(1024),
            BenchType::LinearAlloc(2048),
            BenchType::LinearAlloc(4096),
            BenchType::LinearAlloc(8192),
            BenchType::LinearAllocPopulate(256),
            BenchType::LinearAllocPopulate(512),
            BenchType::LinearAllocPopulate(1024),
            BenchType::LinearAllocPopulate(2048),
            BenchType::LinearAllocPopulate(4096),
            BenchType::LinearAllocPopulate(8192),
            BenchType::MmapWriteMunmap,
            BenchType::MmapWriteMunmapPopulate,
        ] {
            unsafe {
                #[derive(Debug, Default)]
                #[repr(C)]
                struct CloneArgs {
                    flags: u64,
                    pidfd: u64,
                    child_tid: u64,
                    parent_tid: u64,
                    exit_signal: u64,
                    stack: u64,
                    stack_size: u64,
                    tls: u64,
                    set_tid: u64,
                    set_tid_size: u64,
                    cgroup: u64,
                }

                let mut args = CloneArgs::default();
                args.exit_signal = libc::SIGCHLD as u64;

                if clone_vm {
                    args.flags = libc::CLONE_VM as u64;
                }

                let stats = libc::mmap(
                    std::ptr::null_mut(),
                    std::mem::size_of::<Statistics>(),
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_ANON | libc::MAP_SHARED,
                    -1,
                    0,
                );
                assert!(stats != libc::MAP_FAILED);
                let stats = &*(stats as *const Statistics);

                let mut children = Vec::new();
                for core_id in 0..192 {
                    let mut stack = vec![0u8; 128 * 1024];
                    args.stack = stack.as_mut_ptr() as u64;
                    args.stack_size = stack.len() as u64;
                    std::mem::forget(stack);

                    let child: i32;
                    core::arch::asm!("
                        syscall
                        test eax, eax
                        jnz  1f
                        mov  rdi, r14
                        mov  rsi, r15
                        call child
                        1:
                    ",
                        inout("eax") libc::SYS_clone3 as i32 => child,
                        in("r14") core_id,
                        in("r15") stats,
                        inout("rdi") &mut args => _,
                        inout("rsi") std::mem::size_of::<CloneArgs>() => _,
                    );

                    children.push(child);
                }

                println!(
                    "\n\n\"{} {:?}\"",
                    if clone_vm { "threads" } else { "processes" },
                    bench_type
                );
                for job_threads in 1..=32 {
                    // Update job info
                    stats.cum_iters.store(0, Ordering::Relaxed);
                    stats.cum_time.store(0, Ordering::Relaxed);
                    stats.start_barrier.store(0, Ordering::Relaxed);
                    stats.end_barrier.store(0, Ordering::Relaxed);
                    *stats.bench_type.get() = bench_type;

                    stats.job.fetch_add(1, Ordering::Release);

                    loop {
                        std::thread::sleep(std::time::Duration::from_millis(5));

                        if stats.end_barrier.load(Ordering::Acquire) == 32 {
                            let iters = stats.cum_iters.load(Ordering::Relaxed);
                            let time = stats.cum_time.load(Ordering::Relaxed);

                            println!("{job_threads:4} {:15.1}", time as f64 / iters as f64);

                            // Done with job!
                            break;
                        }
                    }
                }

                for child in children {
                    libc::kill(child as i32, libc::SIGKILL);
                }
            }
        }
    }
}
