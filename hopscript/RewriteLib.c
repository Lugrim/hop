#include "RewriteLib.h"
// #include "FakeJs.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
// strcmp
#include <string.h>
// mprotect
#include <sys/mman.h>
// disassembly
#include <capstone/capstone.h>
#include <capstone/x86.h>

#include "bglhopscript_types.h"

#if defined(BENCH) || defined(DBG)
#include <signal.h>
#define SIGTRAP 5
#endif

#ifdef DEBUG_VERBOSE
#include <locale.h>
#endif

#define MIN_INSTR_SIZE 5
#define MAX_INSTR_SIZE 15

////////////
// MACROS //
////////////
int next_entry = 0;

/////////////
// GLOBALS //
/////////////
// char** already_rewritten;

#define PROTECTED_SIZE 64

void* last_protects[PROTECTED_SIZE];
uint16_t protected = 0;

long pagesize;

///////////////
// FUNCTIONS //
///////////////

#ifdef TRACE_HIT_MISS
long space = 0;
long** hits;
long** misses;
long* sizes;
long module_count = 0;

void print_stats() {
	fprintf(stderr, "===== Stats =====\n");
	for (int mod = 0; mod < module_count; mod ++) {
		fprintf(stderr, "== Module %d ==\n", mod);

		long n = sizes[mod];
		
		long hit_sum = 0;
		long miss_sum = 0;

		long *hop_hit_counters = hits[mod];
		long *hop_miss_counters = misses[mod];
		
		for(int i = 0; i < n; i++) {
			hit_sum += hop_hit_counters[i];
			miss_sum += hop_miss_counters[i];
// #ifdef DEBUG_VERBOSE
			if (hop_hit_counters[i] != 0 || hop_miss_counters[i] != 0) {
			fprintf(stderr, "= Access %d =\n\tRewritten executed cache hits: %'ld\n\tCache misses: %'ld\n",
					i,
					hop_hit_counters[i],
					hop_miss_counters[i]);
			}
// #endif
		}

		fprintf(stderr, "= Total =\n\tRewritten executed cache hits: %'ld\n\tCache misses: %'ld\n", hit_sum, miss_sum);
	}
	fprintf(stderr, "===============\n");
}
#endif

#ifdef COUNT_WHATS_HAPPENING
long calls_to_rewrite_opcode = 0;
long first_call_to_rewrite_opcode = 0;
long could_do_find_instruction = 0;
long can_rewrite_instruction = 0;
long actually_rewrote = 0;

void print_what_happened() {
	fprintf(stderr, "=== WHAT HAPPENED? ===\n");
	fprintf(stderr, "\tcalls_to_rewrite_opcode = %d\n", calls_to_rewrite_opcode);
	fprintf(stderr, "\tfirst_call_to_rewrite_opcode = %d\n", first_call_to_rewrite_opcode);
	fprintf(stderr, "\tcould_do_find_instruction = %d\n", could_do_find_instruction);
	fprintf(stderr, "\tcan_rewrite_instruction = %d\n", can_rewrite_instruction);
	fprintf(stderr, "\tactually_rewrote = %d\n", actually_rewrote);
	fprintf(stderr, "======================\n");
}
#endif

void init_rewrite_lib(
#ifdef TRACE_HIT_MISS
		long* hit, long* miss, long* increment,
#endif
		long n
		)
{
	static int init = 0;
    // already_rewritten = rewritten_locations;
	if (init == 0) {
    	pagesize = sysconf(_SC_PAGE_SIZE);
#ifdef DEBUG_VERBOSE
		fprintf(stderr, "System information: page size is %ld bytes\n", pagesize);
		setlocale(LC_NUMERIC, "");
#endif
		init = 1;

#ifdef TRACE_HIT_MISS
		space = 10;
		hits = calloc(space, sizeof(long*));
		misses = calloc(space, sizeof(long*));
		sizes = calloc(space, sizeof(long));
		atexit( print_stats );
#endif

#ifdef COUNT_WHATS_HAPPENING
		atexit( print_what_happened );
#endif
	}

#ifdef TRACE_HIT_MISS
	if (module_count == space - 1) {
		space *= 2;
		hits = realloc(hits, sizeof(long*) * space);
		misses = realloc(misses, sizeof(long*) * space);
		sizes = realloc(sizes, sizeof(long) * space);
	}

	hits[module_count] = hit;
	misses[module_count] = miss;
	sizes[module_count] = n;

	module_count++;
#endif
}

void free_disassemble(csh* disas_handle, cs_insn** disas_insn, size_t disas_count)
{
    if (*disas_insn != NULL) {
        cs_free(*disas_insn, disas_count);
        *disas_insn = NULL;
    }
    if (disas_handle != NULL && *disas_handle != 0) {
        cs_close(disas_handle);
        *disas_handle = 0;
    }
}

/////////////////////////////////////////////////////////
///// DISASSEMBLE AND CHECK VALIDITY OF INSTRUCTION /////
/////////////////////////////////////////////////////////
int disassemble(void* location, cs_insn** disas_insn, size_t* disas_count)
{
    // capstone data structures
    csh disas_handle = 0; // Disassembly handle

    // START DISASSEMBLER //
    // TODO switch back to CS_MODE_32 when debugging for 32-bit mode
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &disas_handle) != CS_ERR_OK) {
#ifdef DEBUG_VERBOSE
        fprintf(stderr, "Could not start disassembler\n");
#endif
        free_disassemble(&disas_handle, disas_insn, *disas_count);
        return 1;
    }

    // SET DETAILED MODE //
    if (cs_option(disas_handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
#ifdef DEBUG_VERBOSE
        fprintf(stderr, "Could not set detailed mode\n");
#endif
        free_disassemble(&disas_handle, disas_insn, *disas_count);
        return 2;
    }

    // TODO: Adjust disassembled size (hardcoded 256 for now)
    *disas_count = cs_disasm(disas_handle,
        location,
        256,
        (uintptr_t)location,
        0,
        disas_insn);
    if (disas_count == NULL || *disas_count <= 0) {
#ifdef DEBUG_VERBOSE
        fprintf(stderr, "Could not disassemble at %p\n", location);
#endif
        free_disassemble(&disas_handle, disas_insn, *disas_count);
        return 3;
    }

    return 0;
}

// Found instruction context
typedef struct {
	size_t length;
	x86_reg offset_reg;
	int next_load_taken;
	x86_reg next_load_reg;
	x86_op_mem next_load_memory;
} FIC;

int look_for_instruction(void* location, long* offset, char** code, FIC* context)
{
    cs_insn* disas_insn = NULL; // Disassembled instruction list
    size_t disas_count = 0; // Disassembled instruction count
    cs_insn ins; // Current / found instruction

    if (disassemble(location, &disas_insn, &disas_count)) {
        return -1;
    }

    // Iterate on disassembled instructions //
    for (size_t i = 0; i < disas_count; i++) {
        ins = disas_insn[i];
#ifdef DEBUG_VERBOSE
        fprintf(stderr, "Instruction #%zd\n", i);
#endif

        // If it is not a mov, it is not our instruction //
        if (strcmp(ins.mnemonic, "mov") != 0 && strcmp(ins.mnemonic, "movsxd") != 0) {
#ifdef DEBUG_VERBOSE
            fprintf(stderr, "\tInstruction at 0x%" PRIx64 " is not a mov, it is a %s\n", ins.address, ins.mnemonic);
#endif
            for (int g = 0; g < ins.detail->groups_count; g++) {
                if (ins.detail->groups[g] == CS_GRP_JUMP
                    || ins.detail->groups[g] == CS_GRP_CALL) {
#ifdef DEBUG_VERBOSE
                    fprintf(stderr, "\t\tJump or call detected, stopping disassembly\n");
#endif
                    free_disassemble(NULL, &disas_insn, disas_count);
                    return -2;
                }
            }
            continue;
        }

#ifdef DEBUG_VERBOSE
        fprintf(stderr, "\t%s %s\n", ins.mnemonic, ins.op_str);
#endif
        // Lets check our operands //
        if (ins.detail->x86.op_count != 2) {
#ifdef DEBUG_VERBOSE
            fprintf(stderr, "\t\tNot an expected operands count\n");
#endif
            continue;
        }

        if (ins.detail->x86.operands[0].type != X86_OP_REG) {
#ifdef DEBUG_VERBOSE
            fprintf(stderr, "\t\tNot a register write: probably not our instruction\n");
#endif
            continue;
        }

        cs_x86_op operand = ins.detail->x86.operands[1];

        uintptr_t reading_at = X86_REL_ADDR(ins);

        // If it's not a memory access, it is not our cache read //
        if (operand.type == X86_OP_MEM) {
            if (ins.detail->x86.encoding.disp_offset == 0) {
#ifdef DEBUG_VERBOSE
                fprintf(stderr, "\t\t\tMemory operand reading has no valid displacement field\n");
#endif
                continue;
            }

#ifdef DEBUG_VERBOSE
            fprintf(stderr, "\t\t\tMemory operand reading from relative address: 0x%" PRIxPTR "\n",
                reading_at);
#endif
            if (reading_at == (uintptr_t)offset) {
#ifdef DEBUG_VERBOSE
                fprintf(stderr, "\t\t\t\tWe found our instruction: 0x%" PRIx64 " %s %s\n", ins.address, ins.mnemonic, ins.op_str);
#endif
                *code = (char*)ins.address;
                context->length = ins.size;
                context->offset_reg = ins.detail->x86.operands[0].reg;

#ifdef DEBUG_VERBOSE
				fprintf(stderr, "disas %s %s\n", ins.mnemonic, ins.op_str);
#endif
				if(i+1 < disas_count) {
					cs_insn next_ins = disas_insn[i+1];

					if(!strcmp("mov", next_ins.mnemonic)
							&& next_ins.detail->x86.op_count == 2
							&& next_ins.detail->x86.operands[0].type == X86_OP_REG
							// Ensure we output where we already outputted
							&& next_ins.detail->x86.operands[0].reg == context->offset_reg
							// Ensure we read from memory
							&& next_ins.detail->x86.operands[1].type == X86_OP_MEM
							// Ensure that we read from from first instruction result
							&& next_ins.detail->x86.operands[1].mem.index == context->offset_reg
							// I wont handle segment registers for now
							&& next_ins.detail->x86.operands[1].mem.segment == X86_REG_INVALID
							) {
						context->next_load_taken = 1;
						context->length += next_ins.size;
						context->next_load_reg = next_ins.detail->x86.operands[0].reg;
						context->next_load_memory = next_ins.detail->x86.operands[1].mem;

#ifdef DEBUG_VERBOSE
						fprintf(stderr, "next  %s %s\n", next_ins.mnemonic, next_ins.op_str);
#endif
					}
					else {
#ifdef DEBUG_VERBOSE
						fprintf(stderr, "Not matching criterias : %s %s\n", next_ins.mnemonic, next_ins.op_str);
#endif
					}
				}
                return 0;
            } else {
#ifdef DEBUG_VERBOSE
                fprintf(stderr, "\t\t\t\tHowever, cache location is 0x%" PRIxPTR "\n", (uintptr_t)offset);
#endif
            }
        } else {
#ifdef DEBUG_VERBOSE
            fprintf(stderr, "\t\t\t\tTODO: Registers and immediates\n");
#endif
        }
    }

    free_disassemble(NULL, &disas_insn, disas_count);
    return -3;
}

void unprotect_page(void* location)
{
    void* pagebeg = (void*)((uintptr_t)location
        & (~(((uintptr_t)pagesize) - 1)));

    if (pagebeg == NULL) {
#ifdef DEBUG_VERBOSE
        fprintf(stderr, "Could not determine page location (location=%p, pagesize=%ld)\n",
            location,
            pagesize);
#endif
        return;
    }
    bool found = false;

	// TODO Switch to ordered (linked ?) list (or C++ list ?)
    for (uint16_t i = 0; i < (protected < PROTECTED_SIZE ? protected : PROTECTED_SIZE); i++) {
        if (last_protects[i] == pagebeg) {
            found = true; // page is already protected
            break;
        }
    }

    if (!found) { // protect the page and record it as protected
        last_protects[(protected ++) % PROTECTED_SIZE] = pagebeg;
        mprotect(pagebeg, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC);
#ifdef DEBUG_VERBOSE
        fprintf(stderr, "unprotecting and recording %p\n", pagebeg);
#endif
    } else {
#ifdef DEBUG_VERBOSE
        fprintf(stderr, "already unprotected %p\n", pagebeg);
#endif
    }

	// If we're too close to a page's end, unprotect the next one
	// WARNING: May have some infinite loop behavior if MAX_INSTR_SIZE > pagesize
	if(location-pagebeg >= pagesize - MAX_INSTR_SIZE) {
		unprotect_page(location + MAX_INSTR_SIZE);
	}
}

void nop_pad(size_t orig_size, size_t i, char* code)
{
    // NOP Padding
    while (orig_size - i >= 9) {
        *((uint32_t*)(code + i)) = 0x841F0F66;
        *((uint32_t*)(code + i + 4)) = 0x00000000;
        *(code + i + 8) = 0x00;
        i += 9;
    }
    // #ifdef DEBUG_VERBOSE
    // 		fprintf(stderr, "i=%d, orig_size-i=%d\n", i, orig_size-i);
    // #endif
    switch (orig_size - i) {
    case 1:
        *(code + i) = 0x90;
        break;
    case 2:
        *((uint16_t*)(code + i)) = 0x9066;
        break;
    case 3:
        *((uint16_t*)(code + i)) = 0x1F0F;
        *(code + i + 2) = 0x00;
        break;
    case 4:
        *((uint32_t*)(code + i)) = 0x00401F0F;
        break;
    case 5:
        *((uint32_t*)(code + i)) = 0x00441F0F;
        *(code + i + 4) = 0x00;
        break;
    case 6:
        *((uint32_t*)(code + i)) = 0x441F0F66;
        *((uint16_t*)(code + i + 4)) = 0x0000;
        break;
    case 7:
        *((uint32_t*)(code + i)) = 0x00801F0F;
        *((uint16_t*)(code + i + 4)) = 0x0000;
        *(code + i + 6) = 0x00;
        break;
    case 8:
        *((uint32_t*)(code + i)) = 0x00841F0F;
        *((uint32_t*)(code + i + 4)) = 0x00000000;
        break;
    default:
        break;
    }
}

int write_first_instr(size_t* i, char* code, FIC context)
{
#ifdef DEBUG_VERBOSE
	fprintf(stderr, "L=%zd\n", context.length);
#endif
	x86_reg reg = context.offset_reg;
	switch (reg) {
	case X86_REG_RAX:
		if(context.length < 7) return 3;
		*((uint16_t*)(code + (size_t)*i)) = 0xC748;
		(*i) += 2;
		code[*i] = 0xC0;
		(*i)++;
		break;
	case X86_REG_RCX:
		if(context.length < 7) return 3;
		*((uint16_t*)(code + (size_t)*i)) = 0xC748;
		(*i) += 2;
		code[*i] = 0xC1;
		(*i)++;
		break;
	case X86_REG_RDX:
		if(context.length < 7) return 3;
		*((uint16_t*)(code + (size_t)*i)) = 0xC748;
		(*i) += 2;
		code[*i] = 0xC2;
		(*i)++;
		break;
	case X86_REG_RBX:
		if(context.length < 7) return 3;
		*((uint16_t*)(code + (size_t)*i)) = 0xC748;
		(*i) += 2;
		code[*i] = 0xC3;
		(*i)++;
		break;
	case X86_REG_RSP:
		if(context.length < 7) return 3;
		*((uint16_t*)(code + (size_t)*i)) = 0xC748;
		(*i) += 2;
		code[*i] = 0xC4;
		(*i)++;
		break;
	case X86_REG_RBP:
		if(context.length < 7) return 3;
		*((uint16_t*)(code + (size_t)*i)) = 0xC748;
		(*i) += 2;
		code[*i] = 0xC5;
		(*i)++;
		break;
	case X86_REG_RSI:
		if(context.length < 7) return 3;
		*((uint16_t*)(code + (size_t)*i)) = 0xC748;
		(*i) += 2;
		code[*i] = 0xC6;
		(*i)++;
		break;
	case X86_REG_RDI:
		if(context.length < 7) return 3;
		*((uint16_t*)(code + (size_t)*i)) = 0xC748;
		(*i) += 2;
		code[*i] = 0xC7;
		(*i)++;
		break;
	case X86_REG_EAX:
		if(context.length < 5) return 3;
		code[*i] = 0xB8;
		(*i)++;
		break;
	case X86_REG_ECX:
		if(context.length < 5) return 3;
		code[*i] = 0xB9;
		(*i)++;
		break;
	case X86_REG_EDX:
		if(context.length < 5) return 3;
		code[*i] = 0xBA;
		(*i)++;
		break;
	case X86_REG_EBX:
		if(context.length < 5) return 3;
		code[*i] = 0xBB;
		(*i)++;
		break;
	case X86_REG_ESP:
		if(context.length < 5) return 3;
		code[*i] = 0xBC;
		(*i)++;
		break;
	case X86_REG_EBP:
		if(context.length < 5) return 3;
		code[*i] = 0xBD;
		(*i)++;
		break;
	case X86_REG_ESI:
		if(context.length < 5) return 3;
		code[*i] = 0xBE;
		(*i)++;
		break;
	case X86_REG_EDI:
		if(context.length < 5) return 3;
		code[*i] = 0xBF;
		(*i)++;
		break;
	default:
#ifdef DEBUG_VERBOSE
		fprintf(stderr, "ERROR: Register case not implemented, skipping rewriting\n");
#endif
		return 2;
		break;
	}
    return 0;
}

int write_second_instr(size_t* i, char* code, FIC context)
{
	// fprintf(stderr, "L2=%zd\n", context.length);
	if(context.length < 7) return 3;
	// x86_reg reg = context.offset_reg;
	unsigned char modrm = 0;
	unsigned char rex = 0b01001000;
	switch (context.next_load_memory.base) {
	case X86_REG_RAX:
		modrm |= 0b10000000;
		break;
	case X86_REG_RCX:
		modrm |= 0b10000001;
		break;
	case X86_REG_RDX:
		modrm |= 0b10000010;
		break;
	case X86_REG_RBX:
		modrm |= 0b10000011;
		break;
	case X86_REG_RSP:
#ifdef DEBUG_VERBOSE
		fprintf(stderr, "ERROR: Register case TODO (Add SIB Byte), skipping rewriting\n");
#endif
		return 2;
		break;
	case X86_REG_RBP:
		modrm |= 0b10000101;
		break;
	case X86_REG_RSI:
		modrm |= 0b10000110;
		break;
	case X86_REG_RDI:
		modrm |= 0b10000111;
		break;
	case X86_REG_R8:
		modrm |= 0b10000000;
		rex |= 0b00000001;
		break;
	case X86_REG_R9:
		modrm |= 0b10000001;
		rex |= 0b00000001;
		break;
	case X86_REG_R10:
		modrm |= 0b10000010;
		rex |= 0b00000001;
		break;
	case X86_REG_R11:
		modrm |= 0b10000011;
		rex |= 0b00000001;
		break;
	case X86_REG_R12:
#ifdef DEBUG_VERBOSE
		fprintf(stderr, "ERROR: Register case TODO (Add SIB Byte), skipping rewriting\n");
#endif
		return 2;
		break;
	case X86_REG_R13:
		modrm |= 0b10000101;
		rex |= 0b00000001;
		break;
	case X86_REG_R14:
		modrm |= 0b10000110;
		rex |= 0b00000001;
		break;
	case X86_REG_R15:
		modrm |= 0b10000111;
		rex |= 0b00000001;
		break;
	default:
#ifdef DEBUG_VERBOSE
		fprintf(stderr, "ERROR: Register case not implemented, skipping rewriting\n");
#endif
		return 2;
		break;
	}
	switch (context.next_load_reg) {
	case X86_REG_RAX:
		modrm |= 0b000000;
		break;
	case X86_REG_RCX:
		modrm |= 0b001000;
		break;
	case X86_REG_RDX:
		modrm |= 0b010000;
		break;
	case X86_REG_RBX:
		modrm |= 0b011000;
		break;
	case X86_REG_RSP:
		modrm |= 0b100000;
		break;
	case X86_REG_RBP:
		modrm |= 0b101000;
		break;
	case X86_REG_RSI:
		modrm |= 0b110000;
		break;
	case X86_REG_RDI:
		modrm |= 0b111000;
		break;
	case X86_REG_R8:
		modrm |= 0b000000;
		rex |= 0b00000100;
		break;
	case X86_REG_R9:
		modrm |= 0b001000;
		rex |= 0b00000100;
		break;
	case X86_REG_R10:
		modrm |= 0b010000;
		rex |= 0b00000100;
		break;
	case X86_REG_R11:
		modrm |= 0b011000;
		rex |= 0b00000100;
		break;
	case X86_REG_R12:
		modrm |= 0b100000;
		rex |= 0b00000100;
		break;
	case X86_REG_R13:
		modrm |= 0b101000;
		rex |= 0b00000100;
		break;
	case X86_REG_R14:
		modrm |= 0b110000;
		rex |= 0b00000100;
		break;
	case X86_REG_R15:
		modrm |= 0b111000;
		rex |= 0b00000100;
		break;
	default:
#ifdef DEBUG_VERBOSE
		fprintf(stderr, "ERROR: Register case not implemented, skipping rewriting\n");
#endif
		return 2;
		break;
	}

	code[*i] = rex;
	(*i)++;
	code[*i] = 0x8B;
	(*i)++;
	code[*i] = modrm;
	(*i)++;
    return 0;
}

void write_offset_at_known_place(char* location, long offset)
{
    *((uint32_t*)location) = (uint32_t)offset;
}

void write_offset(char* location, long offset, size_t* i)
{
    *((uint32_t*)location) = (uint32_t)offset;
    (*i) += 4;
}

///////////////////////
// REWRITE AN OPCODE //
///////////////////////
#define COMPUTE_OFFSET(o_off, o_mul, val) ((o_mul)*(val)+(o_off))
/** Return codes:
 *  0 : OK
 *  1 : Instruction not found
 *  2 : Destination register unimplemented
 *  3 : Not enough space for instruction with immediates
 *  4 : Offset too big for targeted instruction size
 *  5 : Already disassembled and was invalid
 */
int rewrite_opcode(
		void* location,
		void* cache,
		void* obj,
		Rewrite_CE* saved_context
#ifdef TRACE_HIT_MISS
		, long* hop_hit_increment
#endif
		)
{
   // fprintf(stderr, "=== RRRRRRRRRRRRRRRRRRRR ===\n");
   static long cnt = 0;
   // struct BgL_jsobjectz00_bgl *o = (struct BgL_jsobjectz00_bgl *)COBJECT(obj);
   struct BgL_jspropertycachez00_bgl *c = (struct BgL_jspropertycachez00_bgl *)cache;
 
#ifdef COUNT_WHATS_HAPPENING
   calls_to_rewrite_opcode++;
#endif	
   // fprintf(stderr, "============ rewrite #%d loc=%d cache=%p obj=%p MATCH=%d\n", cnt++, c->BgL_pointz00, cache, obj, o->BgL_cmapz00 == c->BgL_imapz00);

	// return 0;

    long offset_value = c->BgL_iindexz00;

	FIC disas_context = 
	{
		5,
		X86_REG_INVALID,
		0,
		X86_REG_INVALID,
		{
			X86_REG_INVALID,
			X86_REG_INVALID,
			X86_REG_INVALID,
			0,
			0,
		},
	};

    size_t i = 0;

    char* code = NULL; // Actual location in code of the instruction to rewrite

#ifdef COUNT_WHATS_HAPPENING
	first_call_to_rewrite_opcode++;
#endif

    long *offset = &(c->BgL_iindexz00);

	// fprintf(stderr, "Offset computed while disassembling is %p\n", offset);

    // If we never rewrote here, search for the instruction we want to rewrite
#ifdef DEBUG_VERBOSE
    fprintf(stderr, "=== starting to look for instruction ===\n");
    int rc =
#endif
		look_for_instruction(location, offset, &code, &disas_context);

    if (code == NULL) {
        fprintf(stderr, "WARNING: could not find instruction (Access %ld)", c->BgL_pointz00);
#ifdef DEBUG_VERBOSE
        fprintf(stderr, ". look_for_instruction returned %d", rc);
#endif
        fprintf(stderr, "\n");
        return 1;
    }

#ifdef COUNT_WHATS_HAPPENING
		could_do_find_instruction++;
#endif

#ifdef DEBUG_VERBOSE
    fprintf(stderr, "=== unprotecting page ===\n");
#endif
    unprotect_page(code);

#ifdef DEBUG_VERBOSE
    fprintf(stderr, "%zd bytes long instruction at %p\n", disas_context.length, code);
#endif

    int wfr;

#ifdef DEBUG_VERBOSE
    fprintf(stderr, "=== rewriting instruction following size... ===\n");
#endif

	if (disas_context.next_load_taken) {
#ifdef DEBUG_VERBOSE
		fprintf(stderr, "This is a pair of instructions!\n");
#endif
		wfr = write_second_instr(&i, code, disas_context);
		saved_context->second_loc = code + i;
		saved_context->status = DOUBLE;
	} else {
		wfr = write_first_instr(&i, code, disas_context);
		saved_context->first_loc = code + i;
		saved_context->status = SINGLE;
	}
	
	saved_context->original_offset = disas_context.next_load_memory.disp;
	saved_context->original_multiplier = disas_context.next_load_memory.scale;

    if (wfr) {
		saved_context->status = INVALID;
#ifdef DEBUG_VERBOSE
#endif
		fprintf(stderr, "ERROR: Could not write following register ; return code %d", wfr);
		if(wfr == 3) {
			fprintf(stderr, " (Not enough space)\n");
#ifdef DEBUG_VERBOSE
#endif
			return 3;
		}
			fprintf(stderr, "\n");
#ifdef DEBUG_VERBOSE
#endif
        return 2;
    }

#ifdef COUNT_WHATS_HAPPENING
		can_rewrite_instruction++;
#endif

#ifdef DEBUG_VERBOSE
    fprintf(stderr, "= rewriting offset =\n");
#endif
	if (disas_context.next_load_taken) {
#ifdef DEBUG_VERBOSE
    fprintf(stderr, "Computed offset: 0x%lx (offset=0x%lx, scale=0x%lx, value=0x%lx)\n",
					COMPUTE_OFFSET(saved_context->original_offset,
					saved_context->original_multiplier,
					offset_value),
					saved_context->original_offset,
					saved_context->original_multiplier,
					offset_value
			);
#endif
			write_offset(code + i,
					COMPUTE_OFFSET(saved_context->original_offset,
					saved_context->original_multiplier,
					offset_value),
					&i);
	} else {
		write_offset(code + i, offset_value, &i);
	}
#ifdef DEBUG_VERBOSE
    fprintf(stderr, "= padding with NOPs =\n");
#endif
    nop_pad(disas_context.length, i, code);

#ifdef TRACE_HIT_MISS
	*hop_hit_increment = 1;
#endif

#ifdef COUNT_WHATS_HAPPENING
	actually_rewrote++;
#endif
    return 0;
}
