/*=====================================================================*/
/*    serrano/prgm/project/hop/3.7.x/hopscript/RewriteLib.h            */
/*    -------------------------------------------------------------    */
/*    Author      :  Manuel Serrano                                    */
/*    Creation    :  Fri Nov 17 17:27:07 2023                          */
/*    Last change :  Thu Feb  1 11:01:16 2024 (serrano)                */
/*    Copyright   :  2023-24 Manuel Serrano                            */
/*    -------------------------------------------------------------    */
/*    RewriteLib.h sample. Compile as follows:                         */
/*      hopc -Ox foo.js -- -copt -DHOP_REWRITE_OPCODE                  */
/*                                                                     */
/*    If only imap should be used then, add the option                 */
/*      --js-cspecs-get "(imap)"                                       */
/*=====================================================================*/
#ifndef REWRITELIB_H
#define REWRITELIB_H

#include <stddef.h>
#include <stdint.h>
#include <bigloo.h>

#define BGL_MODULE_TYPE_DEFINITIONS
#include "bglhopscript_types.h"

typedef enum {
	Nothing = 0,
	Disassemble = 1,
	Mprotect = 2,
	Rewrite_Pair = 3,
	Rewrite_With_Fallback = 4,
	Rewrite_In_A_Buffer = 5,
	Swap_Some_Bytes_Around = 6,
} What_Can_RewriteLib_Do;

typedef struct BgL_threadz00_bgl {
   header_t header;
   obj_t widening;
   obj_t BgL_namez00;
} *BgL_threadz00_bglt;

typedef enum {
	UNTOUCHED = 0,
	SINGLE,
	DOUBLE,
	INVALID,
} Rewrite_Status;

// RewriteLib cache entry
typedef struct {
	char* first_loc;
	unsigned long first_offset;
	char* second_loc;
	unsigned long second_offset;
	unsigned long original_offset;
	unsigned long original_multiplier;
	Rewrite_Status status;
} Rewrite_CE;

struct hop_rewriteinfo {
   void *labeladdr;
   Rewrite_CE saved_context;
};

extern int What_Should_RewriteLib_Do;

#ifndef FAKE_JS_H
// #include "FakeJs.h"
#endif

////////////
// MACROS //
////////////

#define WRITE_OFFSET_AT_KNOWN_PLACE(location, offset) *((uint32_t*)(location)) = (uint32_t)(offset);

#define DOUBLE_SWAP(buffer, type) \
	{ \
	static long tmp = 0; \
	tmp = *((long*) (buffer)); \
	volatile type swaptmp = *((type*) (buffer)); \
	*((type*) (buffer)) = *((type*) ((buffer) + sizeof(type))); \
	*((type*) ((buffer) + sizeof(type))) = swaptmp; \
	swaptmp = *((type*) (buffer)); \
	*((type*) (buffer)) = *((type*) ((buffer) + sizeof(type))); \
	*((type*) ((buffer) + sizeof(type))) = swaptmp; \
	if(tmp != *((long*) (buffer))) \
		fprintf(stderr, "INSTRUCTIONS DIFFER WHEN SWAPPING BYTES\n"); \
	}

// Binary dynamic rewriting macros
#define BINREWRITELIB_REWRITEINFO(n) \
   ((hop_rewriteinfo[n].labeladdr = &&BINREWRITELIB_EXPAND_LABEL(n)), (obj_t)(&(hop_rewriteinfo[n])))

#define BINREWRITELIB_EXPAND_LABEL(uid) LBL_HOPC_ ## uid ## _MOV_REWRITE

#define BINREWRITELIB_CACHE_HIT(uid) \
	BINREWRITELIB_EXPAND_LABEL(uid):

#define BINREWRITELIB_COMPUTE_OFFSET(o_off, o_mul, val) ((o_mul)*(val)+(o_off))

#define BINREWRITELIB_CACHE_MISS_32(obj, uid, cache) \
			struct BgL_jspropertycachez00_bgl *RwL_cache = (struct BgL_jspropertycachez00_bgl *)COBJECT(cache); \
			struct hop_rewriteinfo *RwL_info = (struct hop_rewriteinfo *)RwL_cache->BgL_rewriteinfoz00; \
			if (RwL_info && RwL_info != BUNSPEC) { \
				Rewrite_CE saved_context = RwL_info->saved_context; \
				switch (saved_context.status) { \
					case SINGLE: \
						if (What_Should_RewriteLib_Do == Swap_Some_Bytes_Around) { \
							DOUBLE_SWAP(saved_context.first_loc, char); \
						} else { \
							WRITE_OFFSET_AT_KNOWN_PLACE(saved_context.first_loc, \
										 RwL_cache->BgL_iindexz00); \
						} \
						break; \
					case DOUBLE: \
						if (What_Should_RewriteLib_Do == Swap_Some_Bytes_Around) { \
							DOUBLE_SWAP(saved_context.second_loc, char); \
						} else { \
							WRITE_OFFSET_AT_KNOWN_PLACE(saved_context.second_loc, \
										 BINREWRITELIB_COMPUTE_OFFSET(saved_context.original_offset, \
											 saved_context.original_multiplier, \
											 RwL_cache->BgL_iindexz00)); \
						} \
						break; \
					case UNTOUCHED: \
						rewrite_opcode(RwL_info->labeladdr, \
									RwL_cache, \
									obj, \
									&(RwL_info->saved_context)); \
						break; \
					case INVALID: \
						break; \
					default: \
						fprintf(stderr, "None of those cases?\n"); \
						break; \
				} \
			}

///////////////
// FUNCTIONS //
///////////////
extern void init_rewrite_lib(
#ifdef TRACE_HIT_MISS
	long* hit, long* miss, long* increment,
#endif
 long n
);
/*
 * Will try to dynamically rewrite an instruction.
 * Requires a valid pcache entry
 */
struct BgL_jspropertycachez00_bgl;
int rewrite_opcode(void* location, void* map, void* obj, Rewrite_CE* saved_context
#ifdef TRACE_HIT_MISS
		, long* hop_hit_increment
#endif
		);

#endif

void write_offset_at_known_place(char* location, long offset);
