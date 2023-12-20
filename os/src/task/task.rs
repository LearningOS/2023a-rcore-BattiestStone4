//! Types related to task management
use alloc::collections::BTreeMap;
use super::TaskContext;
use crate::config::TRAP_CONTEXT_BASE;
use crate::mm::{
    kernel_stack_position, MapPermission, MemorySet, PhysPageNum, VirtAddr, KERNEL_SPACE,
};
use crate::trap::{trap_handler, TrapContext};

/// The task control block (TCB) of a task.
pub struct TaskControlBlock {
    /// Save task context
    pub task_cx: TaskContext,

    /// Maintain the execution status of the current process
    pub task_status: TaskStatus,

    /// Application address space
    pub memory_set: MemorySet,

    /// The phys page number of trap context
    pub trap_cx_ppn: PhysPageNum,

    /// The size(top addr) of program which is loaded from elf file
    pub base_size: usize,

    /// Heap bottom
    pub heap_bottom: usize,

    /// Program break
    pub program_brk: usize,

    /// Start time
    pub start_time: Option<usize>,
    
    /// Syscall counts
    pub syscall_counts: BTreeMap<usize, u32>
}

impl TaskControlBlock {
    /// get the trap context
    pub fn get_trap_cx(&self) -> &'static mut TrapContext {
        self.trap_cx_ppn.get_mut()
    }
    /// get the user token
    pub fn get_user_token(&self) -> usize {
        self.memory_set.token()
    }
    /// Based on the elf info in program, build the contents of task in a new address space
    pub fn new(elf_data: &[u8], app_id: usize) -> Self {
        // memory_set with elf program headers/trampoline/trap context/user stack
        let (memory_set, user_sp, entry_point) = MemorySet::from_elf(elf_data);
        debug!("[kernel] app {} entry_point {}", app_id, entry_point);
        let trap_cx_ppn = memory_set
            .translate(VirtAddr::from(TRAP_CONTEXT_BASE).into())
            .unwrap()
            .ppn();
        let task_status = TaskStatus::Ready;
        // map a kernel-stack in kernel space
        let (kernel_stack_bottom, kernel_stack_top) = kernel_stack_position(app_id);
        KERNEL_SPACE.exclusive_access().insert_framed_area(
            kernel_stack_bottom.into(),
            kernel_stack_top.into(),
            MapPermission::R | MapPermission::W,
        );
        let task_control_block = Self {
            task_status,
            task_cx: TaskContext::goto_trap_return(kernel_stack_top),
            memory_set,
            trap_cx_ppn,
            base_size: user_sp,
            heap_bottom: user_sp,
            program_brk: user_sp,
            start_time: None,
            syscall_counts: BTreeMap::new(),
        };
        // prepare TrapContext in user space
        let trap_cx = task_control_block.get_trap_cx();
        *trap_cx = TrapContext::app_init_context(
            entry_point,
            user_sp,
            KERNEL_SPACE.exclusive_access().token(),
            kernel_stack_top,
            trap_handler as usize,
        );
        task_control_block
    }
    /// change the location of the program break. return None if failed.
    pub fn change_program_brk(&mut self, size: i32) -> Option<usize> {
        let old_break = self.program_brk;
        let new_brk = self.program_brk as isize + size as isize;
        if new_brk < self.heap_bottom as isize {
            return None;
        }
        let result = if size < 0 {
            self.memory_set
                .shrink_to(VirtAddr(self.heap_bottom), VirtAddr(new_brk as usize))
        } else {
            self.memory_set
                .append_to(VirtAddr(self.heap_bottom), VirtAddr(new_brk as usize))
        };
        if result {
            self.program_brk = new_brk as usize;
            Some(old_break)
        } else {
            None
        }
    }

    ///increase syscall count 
    pub fn add_syscall_count(&mut self, syscall_id: usize) {
        *self.syscall_counts.entry(syscall_id).or_insert(0) += 1;
    }

    /// set task start time
    pub fn set_start_time(&mut self, start_time: usize) {
        if self.start_time.is_none() {
            self.start_time = Some(start_time);
        }
    }

    /// get syscall count by id
    pub fn get_syscall_count(&self, syscall_id: usize) -> u32 {
        self.syscall_counts.get(&syscall_id).map_or(0, |v| *v)
    }
    /// mmap
    pub fn mmap(&mut self, start: VirtAddr, end: VirtAddr, perm: MapPermission) -> isize {
        if self.is_page_alloc(start, end) {
            return -1;
        }
        if self.memory_set.try_insert_framed_area(start, end, perm).is_ok() {
            0
        } else {
            -1
        }
    }
    /// is page alloc?
    pub fn is_page_alloc(&self, start: VirtAddr, end: VirtAddr) -> bool {
        self.memory_set.is_intersecting_with_range(start.floor(), end.ceil())
    }
    /// munmap
    pub fn munmap(&mut self, start: VirtAddr, end: VirtAddr) -> isize {
        if self.memory_set.try_munmap(start, end).is_ok() {
            0
        } else {
            -1
        }
    }
}

#[derive(Copy, Clone, PartialEq)]
/// task status: UnInit, Ready, Running, Exited
pub enum TaskStatus {
    /// uninitialized
    UnInit,
    /// ready to run
    Ready,
    /// running
    Running,
    /// exited
    Exited,
}
