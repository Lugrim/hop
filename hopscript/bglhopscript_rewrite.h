/*=====================================================================*/
/*    .../prgm/project/hop/hop/hopscript/bglhopscript_rewrite.h        */
/*    -------------------------------------------------------------    */
/*    Author      :  Manuel Serrano                                    */
/*    Creation    :  Fri Feb 11 09:35:38 2022                          */
/*    Last change :  Wed Nov 15 11:40:00 2023 (serrano)                */
/*    Copyright   :  2022-23 Manuel Serrano                            */
/*    -------------------------------------------------------------    */
/*    Code rewrite (patching) macros.                                  */
/*=====================================================================*/
#ifndef BGLHOPSCRIPT_REWRITE_H 
#define BGLHOPSCRIPT_REWRITE_H

/*---------------------------------------------------------------------*/
/*    Dynamic code patching                                            */
/*---------------------------------------------------------------------*/
#if !defined(MODE_REWRITE_OPCODE)
#  define HOP_REWRITE_LOCATIONS(n)
#  define HOP_REWRITE_INIT(n)
#  define HOP_REWRITE_CACHE_HIT(n) 
#  define HOP_REWRITE_CACHE_MISS(n, obj)
#else
#  include "RewriteLib.h"

#  define HOP_REWRITE_LOCATIONS(n) \
   static Rewrite_CE hop_rewrite_locations[n] = { NULL }
#  define HOP_REWRITE_INIT() \
     init_rewrite_lib();
#  define HOP_REWRITE_CACHE_HIT(n) \
     BINREWRITELIB_EXPAND_LABEL(n):
#  define HOP_REWRITE_CACHE_MISS(n, obj) \
     BINREWRITELIB_CACHE_MISS_32(n, &(__bgl_pcache[((long) n)]), obj, &hop_rewrite_locations[n])
#endif

#endif

