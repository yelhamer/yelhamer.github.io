---
title: Reversing Linux' Seccomp Berkley Packet Filters
categories: [REVERSING, SANDBOX]
tags: [reversing, linux, sandbox, seccomp, bpf]
---


# Synopsis

Linux offers a process/thread sandboxing technology called Secure Computing, or seccomp in short. This technology focuses mostly on the syscalls being made by a process, and it is used by a wide-range of modern software to serve varying purposes. Despite it practicality and its popularity, the amount of online content which deals with this technology remains modest, and that is why I am writing this blog post.

Throughout this post, I aim to provide information which is essential to understanding how seccomp filters work, and more specificall, how to reverse them; As well as a practical example at the second part of this post. However, this post is by no means an extensive guide on seccomp/seccomp-BPF, but rather a document which will help you browse through the reference material (instruction set per se) faster and more efficiently.


# Overview of Seccomp-BPF


## Introduction to Seccomp:

Seccomp (Secure Computing) is a Linux security feature which aims to restrict the type of syscalls being made by a process. Once a process configures its seccomp state, each subsequent syscall made by that process is verified by the seccomp faccility for whether it is allowed to run or not.

It is often compared to the OpenBSD [pledge()]https://man.openbsd.org/pledge.2() syscall, in the sense that they both perform somewhat the same functionality. The exception to this comparison is that Linux' seccomp facility is more complex than *pledge()*, notably, because it provides more-tweakable testing conditions, as well as more performable actions than its FreeBSD counterpart.

A process can set up its seccomp facility by calling either the [seccomp()](https://man7.org/linux/man-pages/man2/seccomp.2.html) or the [prctl()](https://man7.org/linux/man-pages/man2/prctl.2.html) syscalls, and supplying the appropriate parameters with regards to each parameter; Among these paremeters are the desired _seccomp mode_ to be deployed, alongside other mode-dependant arguments.

Currently, there exists two modes for seccomp: **Strict Mode** and **Filter Mode**.

### Strict Mode:

In this mode, only the **read()**, **write()**, and **_exit()** syscalls are allowed to be made by the process. It can be set up by either:

- Calling the **prctl()** syscall as follows:

```c
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT)
```

- Calling the **seccomp()** syscall as follows:

```c
seccomp(SECCOMP_SET_MODE_STRICT, 0, NULL)
```

The two forms are functionally identicall.

### Filter Mode:

The other mode is _filter mode_, which provides more flexibility than the previous mode (_strict mode_). In this mode, The process can configure: 

1. Which syscalls are allowed to be made.
2. Which syscalls are forbidden.
3. Which syscalls are allowed conditionally depending on the calling arguments; For example, a process can prohibit reading from a specific file descriptor (_stdin_ per se), and this is by filtering-out calls to the **read()** syscall with the first argument being equal to 0.
4. The action be performed after each match: kill the calling process, kill the calling thread, raise a SIGSYS, etc.

This seccomp mode can be set up quickly by either:

- Calling the **prctl()** syscall as follows:

```c
prctl(PR_SET_NO_NEW_PRIVS, 1);    // Mandatory operation
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, filter);
```

- Calling the **seccomp()** syscall as follows:

```c
prctl(PR_SET_NO_NEW_PRIVS, 1);    // Mandatory operation
seccomp(SECCOMP_SET_MODE_FILTER, 0, filter);
```

The syscalls' ACL as well as the actions to be executed are supplied to seccomp by means of a Berkley Packet Filter, which we will look at in more detail later this article; And the the first **prctl()** call is required if the calling thread does not have the _CAP_SYS_ADMIN_ capability. See the [capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html) and [seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html) man pages for more information.


## Significance in The Context of Cyber Security.

Seccomp is used by a plethora of [modern-day software](https://en.wikipedia.org/wiki/Seccomp#Software_using_seccomp_or_seccomp-bpf), and can be useful in many different situations; For example, when implementing process or thread isolation. It can also be used as an extra protection layer against control-flow hijacking attacks, by restricting the syscalls that a potential threat actor can make; For example, prohibiting the use of the **system()** syscall and thus preventing certain ret2libc scenarios.

Seccomp could also be potentially utilized by malware authors to obfuscate the control flow of a program, as well as hiding it in regular software. This can be accomplished by taking advantage of BPF programs' ability to send certain signals to the calling process, as well as their ability to communicate with the seccomp agent; The respective handler of these two actions can both be modified in certain instances by the calling thread to preform a certain pre-defined function. In addition to this, these actions (sending signals and calling the agent) could be programmed to be triggered only when a certain condition is achieved, such as the **write()** syscall attempting to write certain data to a specific file descriptor; This could be utilized to execute specific code only when certain conditions are met.

All of this is can be programmed by means of Berkley Packet Filters, which we will look at in the next section.


## Berkley Packet Filters:

The Berkley Packet Filter is a technology that was originally created for the purpose of analyzing and filtering network packets; It consists of a 32 bit virtual machine with a simple instruction set, and it is charactarized by:

- **Fixed-length instructions**: Each opcode is 64 bits long.
- **11 32-bit Registers**: R0-R10, wherein R0 is the accumulator register.
- **scratch memory**: Contains 16 32-bit cells addressable from 0-15.
- **packet-focused execution context**: Unless specifically , data references are usually made with relation to the object being filtered, as opposed to the memory as with popular architectures.

Although BPF was created with the purpose of processing network packets in mind, its rigidity made it a good candidate to be used in the seccomp project at the time of its conception; The only aspect that is particular to seccomp-BPF is that it adds some system-specific functionalities (by means of return values), as well as operating on the seccomp syscall-information structure rather than a network packet. Other than that, everything remains the same including the virtual machine as well as its instructions set.

### The Filter Machine's Instruction set:

BPF instructions are encoded using the following fixed format:

| 8 bits (LSB) | 4 bits       | 4 bits       | 16 bits | 32 bits (MSB) |
| :---:        | :---:        | :---:        | :---:   | :---:         |
| opcode       | dst register | src register | offset  | immediate     |

The least significant byte is futher divided into the following field:

| 3 bits (LSB)      | 5 bits (MSB)         |
| :---:             | :---:                |
| Instruction Class | Class-dependant Data |

The 3 lower bits encode the instruction class, which can be either of the following:

| Value | Class     | Description    		                     |
| :---: | :---:     | :---:                                          |
| 0x0   | BPF\_LD    | non-standard load operations                   |
| 0x1   | BPF\_LDX   | load into register operations                  |
| 0x2   | BPF\_ST    | scratch-memory store from immediate operations |
| 0x3   | BPF\_STX   | scratch-memory store from register operations  |
| 0x4   | BPF\_ALU   | 32-bit arithmetic operations                   |
| 0x5   | BPF\_JMP   | 64-bit jump operations                         |
| 0x6   | BPF\_JMP32 | 32-bit jump operations                         |
| 0x7   | BPF\_ALU64 | 64-bit arithmetic operations                   |

In the Arithmetic Instruction class (_BPF\_ALU_) for example, the least significant byte is organized as follows:

| 3 bits (LSB)      | 1 bit | 4 bits (MSB) |
| :--:              | :--:  | :--:         |
| Instruction Class | src   | opcode       |

Where the 4th bit specifies whether to use the _src\_register_ or the _immediate value_ as a source operand.

The remaining 4 bits specify the type of arithmetic operation to perform; For example, some instructions within the _BPF\_ALU_ class include: _BPF\_ADD_, _BPF\_MUL_, _BPF\_XOR_, and _BPF\_RSH_ among others.

A detailed description of the instruction set can be found on [The Linux Kernel Archives](https://docs.kernel.org/bpf/instruction-set.html).


### The Context of a Seccomp Filter Machine:

The context of a Berkley Filter Machine consists of its _registers_, its _scratch memory_, and the main part which is the _filtered-object_. In Network Berkley Packet Filters, that object is a network packet; In the seccomp environment however, that object is the seccomp data structure.

The seccomp data structure is defined in the [linux/seccomp.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/seccomp.h#L53) header file, and it contains the following information on the syscall being made:

- **nr**: The number of syscall being made. For example 59 for the execve() syscall.
- **arch**: Stores the system call convention ([Further Reading](https://blog.packagecloud.io/the-definitive-guide-to-linux-system-calls/)).
- **instruction_pointer**: The contents of the eip/rip register at the time the syscall was made.
- **args**: An array of 6 arguments of size 64 bits.

As a result, the _ld_ (load) instructions for example, will operate mainly on this structure unless specifically told not to by setting the _BPF\_IMM_ bit.


### The Actions of a Seccomp Filter Machine:

The outcome action of a seccomp BPF program — thereby the action it performs — is determined by its return value. There are 8 defined return values for seccomp-BPF in the [linux/seccomp.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/seccomp.h#L29) header file; The following table defines them in order of importance:

| Return Value               | Semantic                                                               |
| :---                       | :---                                                                   |
| SECCOMP\_RET\_KILL_PROCESS | Kills the calling process                                              |
| SECCOMP\_RET\_KILL         | Kills the calling thread. (is a synonym of SECCOM_RET_KILL)            |
| SECCOMP\_RET\_ALLOW        | Allow the syscall without logging it                                   |
| SECCOMP\_RET\_TRAP         | Disallows the requested syscall and raises a SIGSYS signal             |
| SECCOMP\_RET\_USER_NOTIF   | Notifies the user space by means of calling user-defined seccomp agent |
| SECCOMP\_RET\_ERRNO        | Sets the errno variable                                                |
| SECCOMP\_RET\_TRACE        | Pass it to tracer (such as ptrace) \|\| Disallow                       |
| SECCOMP\_RET\_LOG          | Log the syscall and then allow it                                      |


## Disassembling BPF Programs:

Given the basic structure of BPF instructions, disassembling them can be a straight forward task. There already exists a [Github Repository](https://github.com/fr0zn/ebpf-diss-asm) which disassembles BPF instructions into the opcodes as defined [here](https://sourceware.org/binutils/docs/as/BPF-Opcodes.html#Load-instructions-for-socket-filters).

## Summary of The First Part:

In this part, we have seen an overview of the seccomp facility, how to set it up, its filter machines, as well as the in-use instruction set.

Next, we are going to attemp to reverse engineer a binary which sets up seccomp for its corresponding processes, more appropriately, we will be reversing the seccomp filter it uses to filter syscalls.



# Practical Example (HTB University CTF):

As a practice problem, we will be taking a look at a reversing challenge that was published during the [HTB UNI CTF](https://ctf.hackthebox.com/event/details/htb-university-ctf-2022-supernatural-hacks-696)

## Preliminary Analysis:

Examining the ELF header — notably the program and section header — shows no discrepancies:

![elf-header](https://raw.githubusercontent.com/yelhamer/yelhamer.github.io/main/assets/posts/imgs/2.png)
_ELF metadata_

Examining the symbols' section however reveals an morsel of interesting information, which is that the program has a dynamic reference to the **prctl()** syscall:

![syms-table](https://raw.githubusercontent.com/yelhamer/yelhamer.github.io/main/assets/posts/imgs/3.png)
_Symbols Table (Functions Only)__

Aside from this, nothing seems out of the ordinary, which means that now it is time to start static analysis.

## Static Analysis:

Opening the main function in **IDA**, we are greeted first with the disassembly of the _main_ function:

![main-function](https://raw.githubusercontent.com/yelhamer/yelhamer.github.io/main/assets/posts/imgs/4.png)
_Disassembly of the main function_

What this code does is the following:

1. Prints out the string: "Say the magic word".
2. Reads a 50-character string from standard input using _fgets_, stores it on the stack, and finally strips out newline characters from the string.
3. Calls a peculiar function named: **install\_filter**, and it does not return anything.

The program then continues execution as normal after the **install\_filter** function returns, and enters the following loop:

![loop](https://raw.githubusercontent.com/yelhamer/yelhamer.github.io/main/assets/posts/imgs/5.png)
_Main function's loop_

This is a for-loop, it executes for 5 iterations, and it is controled by a stack variable **$rbp-4** which is incremented by 1 with each iteration.

The **$rbp-4** variable is used to iterate through the input string (password) in chunks of 5 characters at a time. With each iteration, the current chunk is first tested for whether it is an empty string or not, then, syscall number _600_ is requested and the **$rbp-4** variable is supplied to it as parameter along with the 5 characters of the current password chunk. The program prints a success message if all loop executes normally for all five chunks, or strangely if each chunk is an empty string.

The thing which arouses suspicion here is that syscall 600 is not a valid Linux syscall, and the syscall number usually stops at around 400 on most Linux systems. Additionally, the fact that the password is being passed to the syscall increases the possibility that this syscall is doing the passphrase verification.

Moving on, Let us look at the **install\_filter()** function which gets called in main before the loop executes. The function's disassembly is as follows:

![install-filter](https://raw.githubusercontent.com/yelhamer/yelhamer.github.io/main/assets/posts/imgs/6.png)
_Disassembly of the install\_filter() function_

The function is not complex and it is easy to understand, it mainly makes 2 calls to **prctl()** (along with 4 additional **perror()** and **exit()** calls for error handling). To figure out what each **prctl()** call is doing, we can look at the [sys/prctl.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/prctl.h) header to dereference the option's numerical value.

The first syscall is being made to **prctl()** with the option _NO\_NEW\_PRIVS_, which is an option we mentioned earlier when talking about installing seccomp-BPF filter.

Examining the second **prctl()** syscall, we can see that is is calling **prctl()** with the following parameters: _0x16_, _0x2_, and _$rbp-0x490_. Using the **prctl()** [man page](https://man7.org/linux/man-pages/man2/prctl.2.html), we can infer the following with regards to each argument:

- **First Argument (_option_)**: This argument specifies the action to be performed. According to the [prctl.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/prctl.h#L68) header file, the option number 0x16 corresponds to the **PR\_SET\_SECCOMP** option, which indicates that the action to be performed is to set up the process' seccomp instance.
- **Second Argument (_arg2_)**: Within the context of the **PR\_SET\_SECCOMP** option, this parameter specifies the seccomp mode to be setup (**STRICT** or **FILTER**). According to the [seccomp.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/seccomp.h#L9) header file, the value 0x2 refers to filter mode. 
- **Third Argument (_$rbp-0x490_)**: When the **prctl()** function call is asked to set up seccomp in filter mode, the third parameter must contain the BPF filter to be installed according to the [struct sock\_fprog](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/filter.h#L31) structure, which is defined as:
    - **len**: A short-unsigned integer which contains the number of instructions in the structure's BPF filter.
    - **filter**: The BPF filter to be installed.

(**Note**: Although the _len_ field is defined as a _short int_, the BPF filter starts at offset 16 within the structure. This is due memory-alignment requirements within structures.)

The next thing to do is to examine the 3rd argument that is being passed to **prctl()**, which is a pointer to a stack variable (_$rbp-0x490_) which contains the BPF filter. This section is filled at the start of the subroutine as follows:

![set-filter](https://raw.githubusercontent.com/yelhamer/yelhamer.github.io/main/assets/posts/imgs/7.png)
_Setting up the filter structure_

First, the contents of the **asc\_2060** global variable is copied into the _filter_ field of the **struct sock\_fprog**, this is done 8 bytes at a time 144 times. After that, the _len_ field of the seccomp filter structure is set to 144; This means that our BPF program contains 144 instructions, and it totals at _144 * 8_ (1152) bytes. The contents of the **asc\_2060** variable do not get changed at any point throughout the program execution:

![asc-2060](https://raw.githubusercontent.com/yelhamer/yelhamer.github.io/main/assets/posts/imgs/10.png)
_xrefs to the asc\_2060 variable_

## Extracting The BPF Filter:

Given the size of the BPF filter (1152) and the offset (0x2060) at which it resides in the file (global variable _asc\_2060_), we can extract it using the following commands:

![bpf-extraction](https://raw.githubusercontent.com/yelhamer/yelhamer.github.io/main/assets/posts/imgs/8.png)
_Extraction of the embedded BPF filter_

After the extraction, we can pass the extracted bpf program to the [disassembly script](https://github.com/fr0zn/ebpf-diss-asm) I mentioned earlier in this post. Doing so gives us the following disassembly:

```assembly
0x0000:   20 00 00 00 04 00 00 00      ldabsw    r0,       r0,  #4		; r0 <- P[4]
0x0001:   15 00 01 00 3e 00 00 c0      jeq       r0,       #-1073741762,+1	; r0 == -1073741762 ? pass : kill_thread
0x0002:   06 00 00 00 00 00 00 00      ret       SECCOMP_RET_KILL
0x0003:   20 00 00 00 00 00 00 00      ldabsw    r0,       r0,  #0		; r0 <- P[0]
0x0004:   15 00 01 00 58 02 00 00      jeq       r0,       #600,+1		; r0 == 600 ? pass : return
0x0005:   06 00 00 00 00 00 ff 7f      ret       SECCOMP_RET_ALLOW
0x0006:   20 00 00 00 10 00 00 00      ldabsw    r0,       r0,  #16		; r0 <- P[16]
0x0007:   15 00 00 21 00 00 00 00      jeq       r0,       #0,  T:+0, F:+33	; r0 == 0 ? pass : goto next_block
[redacted block 1]
0x0029:   15 00 00 21 01 00 00 00      jeq       r0,       #1,  T:+0, F:+33	; r0 == 1 ? pass : goto next_block
[redacted block 2]
0x004b:   15 00 00 21 02 00 00 00      jeq       r0,       #2,  T:+0, F:+33	; r0 == 2 ? pass : goto_next_block
[redacted block 3]
0x006d:   15 00 00 21 03 00 00 00      jeq       r0,       #3,  T:+0, F:+33	; r0 == 3 ? pass : goto_next_block
[redacted block 4]
0x008f:   06 00 00 00 00 00 00 00      ret       SECCOMP_RET_KILL
```

Some blocks of code have been redacted to illustrate the general structure of the program, and because those blocks are identical except for 2 immediate values in each block; We will come back to them later on.

In making sense of the previous assembly, one should bare in mind that the functionality of each the operands (specifically _src_ and _dst_ registers) depends heavily on the instruction being executed. For example, in the **ldw** instruction the first operand is the destination, wheras in the **stw** instruction it is the source; Additionally, some instructions ignore certain operands, such as **ldw** ignoring the _second_ operand, and **ldxw** ignoring the _first_ operand.

This makes reversing the progrma slightly more difficult, and the capstone engine provides a more intuitive disassembly (as shown in the following figure); However, for some reason, capstone would fail to disassemble certain BPF instructions on my machine, notably the **stw** instruction; Therefore I will continue using the github script in this post, and will update it if I get around to solving the issue I am having the feature.

![capstone-disassm](https://raw.githubusercontent.com/yelhamer/yelhamer.github.io/main/assets/posts/imgs/9.png)
_Disassembly according to capstone's python module_


## Reversing the BPF Program:

To understand the exact action performed by each instruction, we can refer to [this instruction set](https://sourceware.org/binutils/docs/as/BPF-Opcodes.html) as well as the FreeBSD bpf [manual page](https://www.freebsd.org/cgi/man.cgi?query=bpf&sektion=4&manpath=FreeBSD+4.7-RELEASE) (specifically, the **FILTER MACHINE** section). With disassembly and reference manual being ready, it is now time to disassemble the BPF program.

The first 2 instructions are making sure that the syscall convention is appropriate. This is done by loading the 32-bit value at the offset 4 of the **sock\_fprog** seccomp structure (which is the object being filtered), then comparing it the appropriate value and killing the thread if the syscall version is not the desired one.

After that, the following 2 instructions are making sure that the BPF is working with the "secret" syscall (number 0x258), which is the one being called by the crackme binary. This is done by retrieving the _nr_ field of the **struct sock\_fprog**, and then comparing it to the immediate value 600; If the values do not match (i.e. the seccomp facility has been summoned by another syscall), then the BPF program returns gracefully (without terminating the calling thread).

Once the BPF filter assures it is working on the _0x258_ syscall, the key-checking part of the program begins executing.

The key-checking algorithm is divided into 4 blocks of identical code (which will be discussed shortly); Which block gets executed depends on the _i_ parameter being passed to the _0x258_ syscall. This gets acoomplished by first getting the _i_ field from the seccomp structure (this gets done by the instruction _0x0006_), after that, a switch statement is used to determine which block gets executed.

Now, it is time to examine the aforementioned blocks. The disassembly of the first block is as follows:

```asm
0x0008:   00 00 00 00 00 00 00 00      ldw       r0,       r0,  #0	; r0 <- 0
0x0009:   02 00 00 00 00 00 00 00      stw       [r0],     #0   	; M[0] <- r0
0x000a:   20 00 00 00 18 00 00 00      ldabsw    r0,       r0,  #24	; r0 <- first_char
0x000b:   61 00 00 00 00 00 00 00      ldxw      r0,       [r0] 	; r1 <- M[0]
0x000c:   1c 00 00 00 00 00 00 00      sub32     r0,       r0   	; r0 <- r0 - r1
0x000d:   02 00 00 00 00 00 00 00      stw       [r0],     #0   	; M[0] <- r0
0x000e:   15 00 01 00 48 00 00 00      jeq       r0,       #72, +1	; r0 == 72 ? pass : kill
0x000f:   06 00 00 00 00 00 00 00      ret       SECCOMP_RET_KILL     
0x0010:   20 00 00 00 20 00 00 00      ldabsw    r0,       r0,  #32	; r0 <- second_char
0x0011:   61 00 00 00 00 00 00 00      ldxw      r0,       [r0] 	; r1 <- M[0]
0x0012:   1c 00 00 00 00 00 00 00      sub32     r0,       r0   	; r0 <- r0 - r1
0x0013:   02 00 00 00 00 00 00 00      stw       [r0],     #0   	; M[0] <- r0
0x0014:   15 00 01 00 0c 00 00 00      jeq       r0,       #12, +1	; r0 == 12 ? pass : kill
0x0015:   06 00 00 00 00 00 00 00      ret       SECCOMP_RET_KILL     
0x0016:   20 00 00 00 28 00 00 00      ldabsw    r0,       r0,  #40	; r0 <- third_char
0x0017:   61 00 00 00 00 00 00 00      ldxw      r0,       [r0] 	; r1 <- M[0]
0x0018:   1c 00 00 00 00 00 00 00      sub32     r0,       r0   	; r0 <- r0 - r1
0x0019:   02 00 00 00 00 00 00 00      stw       [r0],     #0   	; M[0] <- r0
0x001a:   15 00 01 00 36 00 00 00      jeq       r0,       #54, +1	; r0 == 54 ? pass : kill
0x001b:   06 00 00 00 00 00 00 00      ret       SECCOMP_RET_KILL     
0x001c:   20 00 00 00 30 00 00 00      ldabsw    r0,       r0,  #48	; r0 <- fourth_char
0x001d:   61 00 00 00 00 00 00 00      ldxw      r0,       [r0] 	; r1 <- M[0]
0x001e:   1c 00 00 00 00 00 00 00      sub32     r0,       r0   	; r0 <- r0 - r1
0x001f:   02 00 00 00 00 00 00 00      stw       [r0],     #0   	; M[0] <- r0
0x0020:   15 00 01 00 45 00 00 00      jeq       r0,       #69, +1	; r0 == 69 ? pass : kill
0x0021:   06 00 00 00 00 00 00 00      ret       SECCOMP_RET_KILL     
0x0022:   20 00 00 00 38 00 00 00      ldabsw    r0,       r0,  #56	; r0 <- fifth_char
0x0023:   61 00 00 00 00 00 00 00      ldxw      r0,       [r0] 	; r1 <- M[0]
0x0024:   1c 00 00 00 00 00 00 00      sub32     r0,       r0   	; r0 <- r0 - r1
0x0025:   02 00 00 00 00 00 00 00      stw       [r0],     #0   	; M[0] <- r0
0x0026:   15 00 01 00 1c 00 00 00      jeq       r0,       #28, +1	; r0 == 28 ? pass : kill
0x0027:   06 00 00 00 00 00 00 00      ret       SECCOMP_RET_KILL     
0x0028:   06 00 00 00 00 00 ff 7f      ret       SECCOMP_RET_ALLOW
```

The first 2 lines initialize the first word of the scratch memory to the value 0. After that, 5 distinct sub-blocks of code ensue which verify each argument.

Each subblock first retrieves the corresponding character and it calculates the difference between it and the scratch-memory variable, then, it replaces the old value of the scratch-memory variable with the new difference, and finally it checks to see if the difference is equal to a specific value.

This is repeated 5 times in each main block for a total of 4 blocks, totalling at 20 characters being tested, which is the length of the key. With this information it is now time to keygen the crackme.

## Solving The Challenge:

Given the set of values being tested against the difference, in addition to the knowledge we have of the program, we can now write a script which gives us the key for this binary:

```python
# differences set
a = [72, 12, 54, 69, 28, 98, 16, 36, 63, 34, 45, 70, 31, 68, 31, 111, -2, 114, -81, 206]
a = [a[i*5:(i+1)*5] for i in range(5)]

flag = []
for arr in a:
    temp = 0
    for elem in arr:
        flag.append(elem+temp)
        temp = elem

flag = "".join(map(chr, flag))
print(f"Flag is: {flag}")
```

Executing this script gives us the flag and the passphrase, which is: `HTB{abr4ca-seccomp!}`

## Summary of The Second Part:

Throughout this practical example, we have seen how to detect if a seccomp state is being set up, as well as how to reverse the filter being used in case that state is in filter mode. We have also seen how how to disassemble as well as how to understand of the symantics of the program using only static analysis, which is crucial knowledge since BPF programs are harder to debug.


# Final Thoughts

In conclusion, this post has covered several aspects of detecting and reverse-engineering syscall sandboxes, as well as detailing portions of their inner workings. The list of points to be kept-in-mind when dealing with seccomp filters can be summed up as the following:

1. When reversing Linux executables, be wary of **prctl()** syscalls, since they might be indicating that the process or thread is installing a syscall filters.
2. Special attention should be paid to the seccomp return values when reversing seccomp-BPF filters, since they essentially define the set of actions that the BPF program at hand can perform.
3. Knowing the opcodes of seccomp-BPF programs, one can modify a process' embedded BPF filters to alter its behaviour. For example, place a _ret SECCOMP\_RET\_ALLOW_ at the start of the BPF filter, in case a piece of malware is prohibiting certain syscalls (possibly with specific arguments) from being made.

If you have any Feedback or would like to reach out to me, feel free to do so on [Twitter](https://twitter.com/yelhamer).

Thank you for your time :)
