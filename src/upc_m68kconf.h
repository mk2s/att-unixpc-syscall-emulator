/* ======================================================================== */
/* runupc Musashi configuration (AT&T UNIX PC / 3B1, MC68010).
 *
 * Kept in the application repo (not in the fetched Musashi dependency) and
 * selected via -DMUSASHI_CNF="upc_m68kconf.h" with src/ on the include path,
 * per Musashi's documented "custom m68kconf.h outside Musashi's directory"
 * mechanism. This keeps the fetched upstream tree pristine.
 *
 * IMPORTANT: the filename is deliberately NOT "m68kconf.h". Musashi includes
 * the config via `#include MUSASHI_CNF` from m68k.h, and a quoted include
 * searches m68k.h's own directory (the dependency root) first, where upstream's
 * stock m68kconf.h lives. A distinct name avoids that collision so our config
 * is the one that resolves (via the src/ include path).
 *
 * Derived from upstream m68kconf.h. The only substantive change from the
 * stock config is enabling the per-instruction hook and binding it directly
 * to our Zig-exported handler `upc_instr_hook`, which is how the emulator
 * intercepts `trap #0` syscalls (see src/runloop.zig). Memory access uses the
 * default global callbacks (m68k_read/write_memory_*), which src/mem.zig
 * exports.
 * ======================================================================== */

#ifndef M68KCONF__HEADER
#define M68KCONF__HEADER

#define M68K_OPT_OFF             0
#define M68K_OPT_ON              1
#define M68K_OPT_SPECIFY_HANDLER 2

/* Not building for MAME. */
#ifndef M68K_COMPILE_FOR_MAME
#define M68K_COMPILE_FOR_MAME      M68K_OPT_OFF
#endif

/* CPU variants. The UNIX PC is a 68010; we only ever call
 * m68k_set_cpu_type(M68K_CPU_TYPE_68010). The other variants are left as
 * upstream defaults (harmless; they only add opcode-table entries). */
#define M68K_EMULATE_010            M68K_OPT_ON
#define M68K_EMULATE_EC020          M68K_OPT_ON
#define M68K_EMULATE_020            M68K_OPT_ON
#define M68K_EMULATE_030            M68K_OPT_ON
#define M68K_EMULATE_040            M68K_OPT_ON

/* Memory: use the global m68k_read_memory_* / m68k_write_memory_* callbacks
 * (exported from src/mem.zig). No separate immediate/PC-relative reads and no
 * predecrement-write special-casing. */
#define M68K_SEPARATE_READS         M68K_OPT_OFF
#define M68K_SIMULATE_PD_WRITES     M68K_OPT_OFF

/* Interrupts: autovectored, auto-clearing (user-mode emulator, no device
 * interrupt sources). */
#define M68K_EMULATE_INT_ACK        M68K_OPT_OFF
#define M68K_INT_ACK_CALLBACK(A)    your_int_ack_handler_function(A)

#define M68K_EMULATE_BKPT_ACK       M68K_OPT_OFF
#define M68K_BKPT_ACK_CALLBACK()    your_bkpt_ack_handler_function()

#define M68K_EMULATE_TRACE          M68K_OPT_OFF

#define M68K_EMULATE_RESET          M68K_OPT_OFF
#define M68K_RESET_CALLBACK()       your_reset_handler_function()

#define M68K_CMPILD_HAS_CALLBACK    M68K_OPT_OFF
#define M68K_CMPILD_CALLBACK(v,r)   your_cmpild_handler_function(v,r)

#define M68K_RTE_HAS_CALLBACK       M68K_OPT_OFF
#define M68K_RTE_CALLBACK()         your_rte_handler_function()

#define M68K_TAS_HAS_CALLBACK       M68K_OPT_OFF
#define M68K_TAS_CALLBACK()         your_tas_handler_function()

#define M68K_ILLG_HAS_CALLBACK      M68K_OPT_OFF
#define M68K_ILLG_CALLBACK(opcode)  your_op_illg_handler_function(opcode)

#define M68K_TRAP_HAS_CALLBACK      M68K_OPT_OFF
#define M68K_TRAP_CALLBACK(trap)    your_op_trap_handler_function(trap)

#define M68K_EMULATE_FC             M68K_OPT_OFF
#define M68K_SET_FC_CALLBACK(A)     your_set_fc_handler_function(A)

#define M68K_MONITOR_PC             M68K_OPT_OFF
#define M68K_SET_PC_CALLBACK(A)     your_pc_changed_handler_function(A)

/* Per-instruction hook: THIS is how we intercept syscalls. The hook fires
 * before each instruction with the PC of the instruction about to execute;
 * runloop.zig checks for the `trap #0` opcode and services the syscall in Zig.
 * Bound directly (OPT_SPECIFY_HANDLER) to the Zig-exported symbol
 * `upc_instr_hook`. */
#define M68K_INSTRUCTION_HOOK       M68K_OPT_SPECIFY_HANDLER
#define M68K_INSTRUCTION_CALLBACK(pc) upc_instr_hook(pc)
/* Declared here so the core sees a prototype when it expands the macro. */
void upc_instr_hook(unsigned int pc);

#define M68K_EMULATE_PREFETCH       M68K_OPT_OFF

#define M68K_EMULATE_ADDRESS_ERROR  M68K_OPT_OFF

#define M68K_LOG_ENABLE             M68K_OPT_OFF
#define M68K_LOG_1010_1111          M68K_OPT_OFF
#define M68K_LOG_TRAP               M68K_OPT_OFF
#define M68K_LOG_FILEHANDLE         some_file_handle

/* PMMU: on for 020+, but we never enable it for the 68010. Left ON to match
 * upstream so the shared opcode tables build identically. */
#define M68K_EMULATE_PMMU           M68K_OPT_ON

#define M68K_USE_64_BIT             M68K_OPT_ON

#endif /* M68KCONF__HEADER */
