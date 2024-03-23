---
title: OSLAB
date: 2024-02-17 +0800
categories: [OS,REVIEW]
tags: [OS]     # TAG names should always be lowercase
---


# OSLAB总结


test
本校的OS实验搬来了XV6，并进行了一些改动，本文一是对OS实验过程的一个记录，二是对操作系统的一些机制进行简单梳理。

## 实验二 SYSCALL

第一个实验没有太多需要记录的，所以直接略过

顾名思义，本实验主要针对XV6中的系统调用设计。其中又涉及到对XV6进程的理解。

### 关于系统调用

系统调用其实就是一个操作系统给用户程序开放的访问内核空间的合法接口。用户程序需要访问内核空间的时候只需要

- 提供系统调用号（存入EAX）
- 触发软中断让系统进入内核空间

内核中的中断处理函数自动根据系统调用号调用对应的内核函数，内核函数将结果将返回值存入EAX，然后回到中断处理函数，最终回到用户空间，用户程序通过读取EAX得到结果

在这个过程中，我想最需要注意的就是系统调用所涉及的上下文切换：

- 这里的上下文切换只是模式切换，与进程调度所涉及的上下文不同，我们可以大致将上下文分成三部分
    - （1）用户级上下文: 正文、数据、用户堆栈以及共享存储区；
    - （2）寄存器上下文: 通用寄存器、程序寄存器(IP)、处理器状态寄存器(EFLAGS)、栈指针(ESP)；
    - （3）系统级上下文: 进程控制块task_struct、内存管理信息(mm_struct、vm_area_struct、pgd、pte)、内核栈。

- 系统调用主要进行进程寄存器上下文的切换。因此，相比进程调度负担少很多

- 这里摘录一段linux中断上下文的描述

> **Interrupt Context**

   When executing an interrupt handler or bottom half, the kernel is in interrupt context. Recall that process context is the mode of operation the kernel is in while it is executing on behalf of a process -- for example, executing a system  call or running a kernel thread. In process context, the current macro  points to the associated task. Furthermore, because a process is coupled to the kernel in process context(进程以进程上文的形式连接到内核中的), process context can sleep or otherwise invoke the scheduler.

   Interrupt context, on the other hand, is not associated with a process. The current macro is not relevant (although it points to the  interrupted process). Without a backing process(由于没有进程的背景),interrupt context cannot sleep -- how would it ever reschedule? Therefore, you cannot call certain functions from interrupt context. If a function sleeps, you cannot use it from your interrupt handler -- this limits  the functions that one can call from an interrupt  handler.(函数在中断处理程序中使用的限制)

   Interrupt context is time critical because the interrupt handler  interrupts other code. Code should be quick and simple. Busy looping is  discouraged. This is a very important point; always keep in mind that your interrupt handler has interrupted other code (possibly even another interrupt handler on a different line!). Because of this asynchronous nature, it is imperative(必须) that all interrupt  handlers be as quick and as simple as possible. As much as possible,  work should be pushed out from the interrupt handler and performed in a  bottom half, which runs at a more convenient time.

   The setup of an interrupt handler's stacks is a configuration option.  Historically, interrupt handlers did not receive their own stacks.  Instead, they would share the stack of the process that they  interrupted[1]. The kernel stack is two pages in size; typically, that  is 8KB on 32-bit architectures and 16KB on 64-bit architectures. Because in this setup interrupt handlers share the stack, they must be  exceptionally frugal with what data they allocate there. Of  course, the kernel stack is limited to begin with, so all kernel code  should be cautious.

  A process is always running. When nothing else is schedulable, the idle task runs. 



- 当然，因为切换了虚拟内存空间，用户空间的资源和内核空间的资源也是不互通的，需要通过特定的函数来实现资源拷贝，比如LINUX的COPY_TO_USER，COPY_FROM_USER 。

### 如何为我们的系统添加一个系统调用

在编译之前完成如下几件事即可

- 注册系统调用（这里需要根据不同的硬件架构注册，因为软中断也需要硬件的信号触发，本校实验默认risc-v因此只需要在syscall.h声明即可，例如是x86 linux 则在"linux_src"/arch/x86/include/generated/asm/syscalls_64.h中）

- 声明内核函数原型（一般在syscall.h)

- 实现内核函数(sys.c(linux))

    

### 实验具体

事实上实验指导书写的非常详细，相当于喂饭了，这里我只记录关于进程的一些重要内容：

首先来看看进程到底是个啥

```c
struct proc {
  struct spinlock lock;

  // p->lock must be held when using these:
  enum procstate state;        // Process state
  struct proc *parent;         // Parent process
  void *chan;                  // If non-zero, sleeping on chan
  int killed;                  // If non-zero, have been killed
  int xstate;                  // Exit status to be returned to parent's wait
  int pid;                     // Process ID

  // these are private to the process, so p->lock need not be held.
  uint64 kstack;               // Virtual address of kernel stack
  uint64 sz;                   // Size of process memory (bytes)
  pagetable_t pagetable;       // User page table
  struct trapframe *trapframe; // data page for trampoline.S
  struct context context;      // swtch() here to run process
  struct file *ofile[NOFILE];  // Open files
  struct inode *cwd;           // Current directory
  char name[16];               // Process name (debugging)
};

```


~~这里贴心的给我们写出了什么时候要加锁，还不感谢proc.h~~



进程状态

    SLEEPING 、 RUNNABLE 和 RUNNING 分别表示睡眠、阻塞和正在运行三个状态
    UNUSED：在进程池中，尚未使用，还没有被分配出去；
    USED：刚从进程池中分配出去，但是此时进程相关资源还没分配；
    ZOMBIE：僵尸状态，当一个进程执行完成的时候，会调用 exit 退出，此时进程会进入这个状态，需要等待父进程调用 wait 来回收子进程所有剩下的资源；

	当一个子进程执行 exit 退出，但是父进程一直没有调用 wait 来回收子进程的资源，这个时候这个子进程就被称为僵尸进程；

	如果子进程退出之前，父进程就已经终止了，此时子进程还在运行，这个进程就称为孤儿进程，孤儿进程会被 init 进程所接管，最后会由 init 进程调用 wait 来释放资源；

再看看fork时子进程是怎么创建的

```c
  // Copy user memory from parent to child.
  if (uvmcopy(p->pagetable, np->pagetable, p->sz) < 0) {
    freeproc(np);
    release(&np->lock);
    return -1;
  }
  np->sz = p->sz;

  np->parent = p;

  // copy saved user registers.
  *(np->trapframe) = *(p->trapframe);

  // Cause fork to return 0 in the child.
  np->trapframe->a0 = 0;

  // increment reference counts on open file descriptors.
  for (i = 0; i < NOFILE; i++)
    if (p->ofile[i]) np->ofile[i] = filedup(p->ofile[i]);
  np->cwd = idup(p->cwd);

  safestrcpy(np->name, p->name, sizeof(p->name));

  pid = np->pid;

  np->state = RUNNABLE;
```



可以看到，子进程几乎是完全独立于父进程的，复制了父进程的寄存器数据，页表，但之后的寄存器数据和叶表变化都不会对父进程有影响，这里和线程就有很大的不同。也就是说，fork复制的大多是数据，而非指针，这就决定了二者的数据独立。当然由于只复制了文件描述符也导致父子进程对于文件是共享的。

剩下的具体实验内容就不多做阐述，跟着指导书的步骤直接写就行，这里写一个相对有趣问题的回答

为什么子进程（4、5、6号进程）的输出之前会 **稳定的** 出现一个`$`符号？（提示：shell程序(`sh.c`)中什么时候打印出`$`符号？）

父进程退出时，调用了wakeup1(original_parent)，而父进程的父进程是sh，sche（）后sh又执行了getcmd死循环因此会打印“$"





## 实验三 LOCK

这个实验的主题是要解决优化锁争用，选的两个典型

- kalloc中的自旋锁（中断关闭）
- bcache中的睡眠锁（允许yield和中断）

实验实现也还是相对直接，甚至不涉及太多系统方面的知识，这里讲一讲对两个问题解决方案的异同点：

- 为什么这两种锁争用的优化方法会不同  *主要原因在我看来还是锁保护的资源性质不同所造成的问题，内存分配器所维护的归根结底是一条freelist，我们的优化方法只是相当于给每一个CPU单独分配了一个接口和区域限制去访问它，这个切分和数据是没有关系的，从不同接口访问所取得的资源本质上是没有差别的，kalloc也没有接受任何参数。而磁盘缓存分配则不同，不同blockno所对应的要取出的资源是不同的，也就是说，我们所面对的数据是需要有自己的标签来寻找的，那么要减少寻找的时间，简单的分割资源限制区域就行不通了，也就是说，这里对区域的分割也要和资源自身的标签相关，那么hash算法就成了自然的一种选择。*

- 当然，这里的并行也是在做区域的切分，因此kalloc中的steal策略在bcache中一样是适用的



## 实验四 页表

这个实验的主题是实现xv6的独立内核页表，不过我总感觉这个优化大概率只会产生负效果。

先来讨论一下，通过实现独立内核页表我们得到了什么吧。

虽然名字叫做独立内核页表，但寻其本质就是我们给每一个进程都额外储存了一份从内核地址空间到该进程用户地址空间的映射，因此我们可以方便地在内核态读取用户空间的资源，好像仅此一个优点。。。

但是为此，我们需要在每次中断上下文切换时，刷新掉宝贵的TLB，让原本cost极少的中断处理变得奢侈，CPU的缓存也需要刷新。我们的优化是为了方便内核函数执行，但执行内核函数必然要执行中断上下文切换，内核态本来就不应该过多读取用户态的数据，为了特殊情况牺牲最普遍情况的性能，只能说是出于教学目的的考虑了。

另外，这样的处理也造成了对资源的极大浪费，相当于我们的用户进程页表资源开销是之前的两倍（每个进程都储存了重复的内核地址索引和用户叶子页表索引）

还有一点就是安全问题，sync实现相当于将用户空间的数据搬到了内核空间中，而且没有也很难做任何安全性上的校验，及其容易产生系统漏洞。



> "Kernel Developers do not put blind faith in anything". When any data is passed to the kernel space from userspace, it is the responsibility of the kernel developer to make sure that everything is sanitized. Just as you check for corner conditions in the functions, it is something similar for the kernel developers. Its a hygienic practice to use copy_from_user() to read the userspace data.



这里贴一下x86 linux copy_to_user的实现

```c
unsigned long _copy_to_user(void __user *to, const void *from, unsigned long n)
{
	might_fault();
	if (should_fail_usercopy())
		return n;
	if (likely(access_ok(to, n))) {
		instrument_copy_to_user(to, from, n);
		n = raw_copy_to_user(to, from, n);
	}
	return n;
}
EXPORT_SYMBOL(_copy_to_user);


/**
 * instrument_copy_to_user - instrument reads of copy_to_user
 * @to: destination address
 * @from: source address
 * @n: number of bytes to copy
 *
 * Instrument reads from kernel memory, that are due to copy_to_user (and
 * variants). The instrumentation must be inserted before the accesses.
 */
static __always_inline void
instrument_copy_to_user(void __user *to, const void *from, unsigned long n)
{
	kasan_check_read(from, n);
	kcsan_check_read(from, n);
	kmsan_copy_to_user(to, from, n, 0);
}

void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
			size_t left)
{
	unsigned long ua_flags;

	if (!kmsan_enabled || kmsan_in_runtime())
		return;
	/*
	 * At this point we've copied the memory already. It's hard to check it
	 * before copying, as the size of actually copied buffer is unknown.
	 */

	/* copy_to_user() may copy zero bytes. No need to check. */
	if (!to_copy)
		return;
	/* Or maybe copy_to_user() failed to copy anything. */
	if (to_copy <= left)
		return;

	ua_flags = user_access_save();
	if ((u64)to < TASK_SIZE) {
		/* This is a user memory access, check it. */
		kmsan_internal_check_memory((void *)from, to_copy - left, to,
					    REASON_COPY_TO_USER);
	} else {
		/* Otherwise this is a kernel memory access. This happens when a
		 * compat syscall passes an argument allocated on the kernel
		 * stack to a real syscall.
		 * Don't check anything, just copy the shadow of the copied
		 * bytes.
		 */
		kmsan_internal_memmove_metadata((void *)to, (void *)from,
						to_copy - left);
	}
	user_access_restore(ua_flags);
}
EXPORT_SYMBOL(kmsan_copy_to_user);


static __always_inline __must_check unsigned long
copy_user_generic(void *to, const void *from, unsigned long len)
{
	stac();
	/*
	 * If CPU has FSRM feature, use 'rep movs'.
	 * Otherwise, use rep_movs_alternative.
	 */
	asm volatile(
		"1:\n\t"
		ALTERNATIVE("rep movsb",
			    "call rep_movs_alternative", ALT_NOT(X86_FEATURE_FSRM))
		"2:\n"
		_ASM_EXTABLE_UA(1b, 2b)
		:"+c" (len), "+D" (to), "+S" (from), ASM_CALL_CONSTRAINT
		: : "memory", "rax");
	clac();
	return len;
}

static __always_inline __must_check unsigned long
raw_copy_to_user(void __user *dst, const void *src, unsigned long size)
{
	return copy_user_generic((__force void *)dst, src, size);
}

```



众所周知，LINUX是使用共享内核页表的，当碰到copy_to/from_user性能成为瓶颈时，LINUX选择使用mmap实现连续高效的物理内存共享，我想这会是更好的解决方案。

具体实验内容指导书写的差不多了，因此不多赘述，借此实验，我想可以研究一下x86 linux的进程页表机制,以下内容参考了此博客[Linux 页表体系 —— 详解虚拟内存如何与物理内存进行映射](https://www.cnblogs.com/binlovetech/p/17571929.html)

这篇文章中最关键的点是说明了内核页表，内核线程，用户虚拟内存空间这三者的关系，

---

处于内核态的进程以及内核线程来说并不能直接访问全局内核页表，它们只能访问内核页表的 copy 副本（事实上也在进程页表中，所以内核所操作的内核页表天然就是独立的），进程的页表分为两个部分，一个是进程用户态页表，另一个就是内核页表的 copy 部分。

fork 系统调用在创建子进程的时候，会拷贝父进程的所有资源，当拷贝父进程的虚拟内存空间的时候，内核会通过  pgd_alloc 函数为子进程创建顶级页表 pgd，在 pgd_alloc 函数中还会调用 pgd_ctor，这个 pgd_ctor 函数会将内核页表拷贝到进程页表中。

---

```c
struct mm_struct {
        struct vm_area_struct  *mmap;               /* list of memory areas */
        struct rb_root         mm_rb;               /* red-black tree of VMAs */
        struct vm_area_struct  *mmap_cache;         /* last used memory area */
        unsigned long          free_area_cache;     /* 1st address space hole */
        pgd_t                  *pgd;                /* page global directory */
        atomic_t               mm_users;            /* address space users */
        atomic_t               mm_count;            /* primary usage counter */
        int                    map_count;           /* number of memory areas */
        struct rw_semaphore    mmap_sem;            /* memory area semaphore */
        spinlock_t             page_table_lock;     /* page table lock */
        struct list_head       mmlist;              /* list of all mm_structs */
        unsigned long          start_code;          /* start address of code */
        unsigned long          end_code;            /* final address of code */
        unsigned long          start_data;          /* start address of data */
        unsigned long          end_data;            /* final address of data */
        unsigned long          start_brk;           /* start address of heap */
        unsigned long          brk;                 /* final address of heap */
        unsigned long          start_stack;         /* start address of stack */
        unsigned long          arg_start;           /* start of arguments */
        unsigned long          arg_end;             /* end of arguments */
        unsigned long          env_start;           /* start of environment */
        unsigned long          env_end;             /* end of environment */
        unsigned long          rss;                 /* pages allocated */
        unsigned long          total_vm;            /* total number of pages */
        unsigned long          locked_vm;           /* number of locked pages */
        unsigned long          def_flags;           /* default access flags */
        unsigned long          cpu_vm_mask;         /* lazy TLB switch mask */
        unsigned long          swap_address;        /* last scanned address */
        unsigned               dumpable:1;          /* can this mm core dump? */
        int                    used_hugetlb;        /* used hugetlb pages? */
        mm_context_t           context;             /* arch-specific data */
        int                    core_waiters;        /* thread core dump waiters */
        struct completion      *core_startup_done;  /* core start completion */
        struct completion      core_done;           /* core end completion */
        rwlock_t               ioctx_list_lock;     /* AIO I/O list lock */
        struct kioctx          *ioctx_list;         /* AIO I/O list */
        struct kioctx          default_kioctx;      /* AIO default I/O context */
};
```

> 进程的虚拟内存空间在内核中是用 struct mm_struct  结构来描述的，每个进程都有自己独立的虚拟内存空间，而进程的虚拟内存到物理内存的映射也是独立的，为了保证每个进程里内存映射的独立进行，所以每个进程都会有独立的页表，而页表的起始地址就存放在 struct mm_struct 结构中的 pgd 属性中。

> 当我们使用 fork 系统调用创建进程的时候，内核在 _do_fork 函数中会通过 copy_process 将父进程的所有资源拷贝到子进程中，这其中也包括父进程的虚拟内存空间。

```c
long _do_fork(unsigned long clone_flags,
       unsigned long stack_start,
       unsigned long stack_size,
       int __user *parent_tidptr,
       int __user *child_tidptr,
       unsigned long tls)
{
              .........  ..........
     struct pid *pid;
     struct task_struct *p;

              .........  ..........
    // 拷贝父进程的所有资源
     p = copy_process(clone_flags, stack_start, stack_size,
         child_tidptr, NULL, trace, tls, NUMA_NO_NODE);

             .........  ..........
}

static __latent_entropy struct task_struct *copy_process(
     unsigned long clone_flags,
     unsigned long stack_start,
     unsigned long stack_size,
     int __user *child_tidptr,
     struct pid *pid,
     int trace,
     unsigned long tls,
     int node)
{

    struct task_struct *p;
    // 为进程创建 task_struct 结构
    p = dup_task_struct(current, node);

        ....... 初始化子进程 ...........

        ....... 开始拷贝父进程资源  .......      

    // 拷贝父进程的虚拟内存空间以及页表
    retval = copy_mm(clone_flags, p);

        ......... 拷贝父进程的其他资源 .........

    // 分配 CPU
    retval = sched_fork(clone_flags, p);
    // 分配 pid
    pid = alloc_pid(p->nsproxy->pid_ns_for_children);

        ...........  .........
}
```

> copy_mm 函数负责处理子进程虚拟内存空间的初始化工作，它会调用 dup_mm 函数，最终在 dup_mm 函数中将父进程虚拟内存空间的所有内容包括父进程的相关页表全部拷贝到子进程中，其中就包括了为子进程分配顶级页表起始地址 pgd。

```c
static int copy_mm(unsigned long clone_flags, struct task_struct *tsk)
{
    ......  ........
    
    mm = dup_mm(tsk, current->mm);
    
    ......  ........
}

/**
 * Allocates a new mm structure and duplicates the provided @oldmm structure
 * content into it.
 */
static struct mm_struct *dup_mm(struct task_struct *tsk,
    struct mm_struct *oldmm)
{
     // 子进程虚拟内存空间，此时还是空的
     struct mm_struct *mm;
     int err;
     // 为子进程申请 mm_struct 结构
     mm = allocate_mm();
     if (!mm)
        goto fail_nomem;
     // 将父进程 mm_struct 结构里的内容全部拷贝到子进程 mm_struct 结构中
     memcpy(mm, oldmm, sizeof(*mm));
     // 为子进程分配顶级页表起始地址并赋值给 mm_struct->pgd
     if (!mm_init(mm, tsk, mm->user_ns))
        goto fail_nomem;
     // 拷贝父进程的虚拟内存空间中的内容以及页表到子进程中
     err = dup_mmap(mm, oldmm);
     if (err)
        goto free_pt;

     return mm;
}
```

> 最后内核会在 mm_init 函数中调用 mm_alloc_pgd，并在 mm_alloc_pgd 函数中通过调用 pgd_alloc 为子进程分配其独立的顶级页表起始地址，赋值给子进程 struct mm_struct 结构中的 pgd 属性。

```c
static struct mm_struct *mm_init(struct mm_struct *mm, struct task_struct *p,
    struct user_namespace *user_ns)
{
    .... 初始化子进程的 mm_struct 结构 ......
    
    // 为子进程分配顶级页表起始地址 pgd
    if (mm_alloc_pgd(mm))
        goto fail_nopgd;

}

static inline int mm_alloc_pgd(struct mm_struct *mm)
{
    // 内核为子进程分配好其顶级页表起始地址之后
    // 赋值给子进程 mm_struct 结构中的 pgd 属性
    mm->pgd = pgd_alloc(mm);
    if (unlikely(!mm->pgd))
        return -ENOMEM;
    return 0;
}
```

> 进程上下文进行切换内容主要包括：1.进程虚拟内存空间的切换。2.寄存器以及进程栈的切换。

```c
/*
 * context_switch - switch to the new MM and the new thread's register state.
 */
static __always_inline struct rq *
context_switch(struct rq *rq, struct task_struct *prev,
           struct task_struct *next, struct rq_flags *rf)
{
    ........  ,,,,,,,,,,

    if (!next->mm) {                                // to kernel

        ........ 内核线程的切换 ,,,,,,,,,,

    } else {                                        // to user
        ........ 用户进程的切换 ,,,,,,,,,,

        membarrier_switch_mm(rq, prev->active_mm, next->mm);
        // 切换进程虚拟内存空间
        switch_mm_irqs_off(prev->active_mm, next->mm, next);
    }

    // 切换 CPU 上下文和进程栈
    switch_to(prev, next, prev);
    barrier();
    return finish_task_switch(prev);
}
```

>  switch_mm_irqs_off 函数负责对进程虚拟内存空间进行切换，其中就包括了调用 load_new_mm_cr3 函数将进程顶级页表起始地址 mm_struct-> pgd 中的虚拟内存地址转换为物理内存地址，并将 pgd 的物理内存地址加载到 cr3 寄存器中。

```c
void switch_mm_irqs_off(struct mm_struct *prev, struct mm_struct *next,
			struct task_struct *tsk)
{
      // 通过 __sme_pa 将 pgd 的虚拟内存地址转换为物理内存地址
      // 并加载到 cr3 寄存器中
      load_new_mm_cr3(next->pgd, new_asid, true);
}
```

> cr3 寄存器中存放的是当前进程顶级页表 pgd 的物理内存地址，不能是虚拟内存地址。

> 进程的上下文在内核中完成切换之后，现在 cr3 寄存器中保存的就是当前进程顶级页表的起始物理内存地址了，当 CPU  通过下图所示的虚拟内存地址访问进程的虚拟内存时，CPU 首先会从 cr3  寄存器中获取到当前进程的顶级页表起始地址，然后从虚拟内存地址中提取出虚拟内存页对应 PTE 在页表内的偏移，通过 页表起始地址 + 页表内偏移 * sizeof(PTE) 这个公式定位到虚拟内存页在页表中所对应的 PTE。而虚拟内存页背后所映射的物理内存页的起始地址就保存在该 PTE  中，随后 CPU 继续从上图所示的虚拟内存地址中提取后半部分——物理内存页内偏移，并通过 物理内存页起始地址 + 物理内存页内偏移就定位到了该物理内存页中一个具体的物理字节上。

> **对于处于内核态的进程以及内核线程来说并不能直接访问内核页表**，它们只能访问内核页表的 copy **副本**，进程的页表分为两个部分，一个是进程用户态页表，另一个就是内核页表的 copy 部分。在 pgd_alloc 函数中还会调用 pgd_ctor，这个 pgd_ctor 函数的主要工作就是将内核页表拷贝到进程页表中。

```c
static inline int mm_alloc_pgd(struct mm_struct *mm)
{
    // 内核为子进程分配好其顶级页表起始地址之后
    // 赋值给子进程 mm_struct 结构中的 pgd 属性
    mm->pgd = pgd_alloc(mm);
    if (unlikely(!mm->pgd))
        return -ENOMEM;
    return 0;
}

pgd_t *pgd_alloc(struct mm_struct *mm)
{
    pgd_t *pgd;
    // 为子进程分配顶级页表
    pgd = _pgd_alloc();
    if (pgd == NULL)
        goto out;

    mm->pgd = pgd;

    ...... 根据配置，与初始化子进程页表 .....
    // 拷贝内核页表到子进程中
    pgd_ctor(mm, pgd);

    ....... 省略 ........
}
```

> 当进程通过系统调用切入到内核态之后，就会使用内核页表的这部分 copy  副本，来访问内核空间虚拟内存映射的物理内存。当进程页表中内核部分的拷贝副本与主内核页表不同步时，进程在内核态就会发生缺页中断，随后会同步主内核页表到进程页表中，这里又是延时拷贝在内核中的一处应用。

> 内核线程有一点和普通的进程不同，内核线程只能运行在内核态，而在内核态中，所有进程看到的虚拟内存空间全部都是一样的，所以对于内核线程来说并不需要为其单独的定义 mm_struct 结构来描述内核虚拟内存空间，内核线程的 struct task_struct 结构中的 mm 属性指向  null，内核线程之间调度是不涉及地址空间切换的，从而避免了无用的 TLB 缓存以及 CPU 高速缓存的刷新。

```c
 struct task_struct {
    // 对于内核线程来说，它并没有自己的地址空间
    // 因为它始终工作在内核空间中，所有进程看到的都是一样的
    struct mm_struct  *mm;
}
```

> 但是内核线程依然需要访问内核空间中的虚拟内存，也就是说内核线程仍然需要内核页表，但是它又没有自己的地址空间,因此当一个内核线程被调度时，它会发现自己的虚拟地址空间为  null，虽然它不会访问用户态的内存，但是它会访问内核内存，聪明的内核会将调度之前的上一个用户态进程的虚拟内存空间 mm_struct  直接赋值给内核线程 task_struct->active_mm 中 。



## 实验五 FS

由于本人对文件系统了解不多，兴趣一般，就是按着指导书的逻辑随便抄抄改改simplefs的代码，这里就不做记录了。

