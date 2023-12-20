//! Process management syscalls
use crate::{
    config::MAX_SYSCALL_NUM,
    config::PAGE_SIZE,
    task::{
        change_program_brk, 
        exit_current_and_run_next, 
        suspend_current_and_run_next,
        current_user_token,
        get_current_start_time,
        get_current_syscall_count,
        TaskStatus,
        mmap,
        munmap,
    },
    timer::get_time_us,
    mm::{
        copy_out_data,
        VirtAddr,
        MapPermission,
    },
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    status: TaskStatus,
    /// The numbers of syscall called by task
    syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    time: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let us = get_time_us();
    let p_ts = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };
    copy_out_data(current_user_token(), ts as *mut u8, &p_ts);
    0
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(ti: *mut TaskInfo) -> isize {
    let mut kti = TaskInfo {
        status: TaskStatus::Running,
        syscall_times: [0; MAX_SYSCALL_NUM],
        time: (get_time_us() - get_current_start_time()) / 1000,
    };
    for syscall_id in 0..MAX_SYSCALL_NUM {
        kti.syscall_times[syscall_id] = get_current_syscall_count(syscall_id);
    }
    copy_out_data(current_user_token(), ti as *mut u8, &kti);
    0
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    if start % PAGE_SIZE != 0 || port & !0x7 != 0 || port & 0x7 == 0 {
        return -1;
    }
    if len == 0 {
        return 0;
    }
    let start_va: VirtAddr = VirtAddr::from(start);
    let end_va: VirtAddr = VirtAddr::from(start + len);
    let mut map_perm = MapPermission::U;
    if port & 1 == 1 {
        map_perm |= MapPermission::R;
    }
    if (port >> 1) & 1 == 1 {
        map_perm |= MapPermission::W;
    }
    if (port >> 2) & 1 == 1 {
        map_perm |= MapPermission::X;
    }
    mmap(start_va, end_va, map_perm)    
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    if start % PAGE_SIZE != 0 {
        return -1;
    }
    if len == 0 {
        return 0;
    }
    munmap(start.into(), (start + len).into())
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
