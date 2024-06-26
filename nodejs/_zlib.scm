;*=====================================================================*/
;*    serrano/prgm/project/hop/hop/nodejs/_zlib.scm                    */
;*    -------------------------------------------------------------    */
;*    Author      :  Manuel Serrano                                    */
;*    Creation    :  Sun Dec 27 19:12:38 2015                          */
;*    Last change :  Mon Feb 20 07:43:37 2023 (serrano)                */
;*    Copyright   :  2015-23 Manuel Serrano                            */
;*    -------------------------------------------------------------    */
;*    Zlib bindings                                                    */
;*=====================================================================*/

;*---------------------------------------------------------------------*/
;*    The module                                                       */
;*---------------------------------------------------------------------*/
(module __nodejs__zlib

   (include "../hopscript/stringthread.sch")
   
   (library hopscript)

   (static  (class JsZlib::JsObject))
   
   (import  __nodejs_uv
	    __nodejs_process)

   (export  (process-zlib ::WorkerHopThread ::JsGlobalObject ::JsObject)))

;*---------------------------------------------------------------------*/
;*    &begin!                                                          */
;*---------------------------------------------------------------------*/
(define __js_strings (&begin!))

;*---------------------------------------------------------------------*/
;*    constructors                                                     */
;*---------------------------------------------------------------------*/
(define-instantiate JsZlib)

;*---------------------------------------------------------------------*/
;*    process-zlib ...                                                 */
;*    -------------------------------------------------------------    */
;*    http://nodejs.org/api/zlib.html                                  */
;*---------------------------------------------------------------------*/
(define (process-zlib %worker %this process)

   (define __init (set! __js_strings (&init!)))
   
   (define (zlib-write this . l)
      (tprint "zlib-write l=" l)
      (error "zlib" "binding not implemented" "write"))
   
   (define (zlib-init this . l)
      (tprint "zlib-init l=" l))

   (define (zlib-close this)
      (error "zlib" "binding not implemented" "close"))
      
   (define (zlib-reset this)
      (error "zlib" "binding not implemented" "reset"))
      
   (define zlib-proto
      (let ((proto (with-access::JsGlobalObject %this (js-object)
		      (js-new %this js-object))))
	 (js-put! proto (& "write")
	    (js-make-function %this zlib-write
	       (js-function-arity 7 0)
	       (js-function-info :name "write" :len 7))
	    #f %this)
	 (js-put! proto (& "init")
	    (js-make-function %this zlib-init
	       (js-function-arity 5 0)
	       (js-function-info :name "init" :len 5))
	    #f %this)
	 (js-put! proto (& "close")
	    (js-make-function %this zlib-close
	       (js-function-arity zlib-close)
	       (js-function-info :name "close" :len 0))
	    #f %this)
	 (js-put! proto (& "reset")
	    (js-make-function %this zlib-reset
	       (js-function-arity 0 0)
	       (js-function-info :name "reset" :len 0))
	    #f %this)
	 proto))
   
   (define (zlib this)
      (instantiateJsZlib
	 (__proto__ zlib-proto)))

   (let* ((zlib (js-make-function %this zlib
		   (js-function-arity 0 0)
		   (js-function-info :name "Zlib" :len 0)
		   :prototype zlib-proto)))
      (js-alist->jsobject
	 `((Zlib . ,zlib))
	 %this) ))

;*---------------------------------------------------------------------*/
;*    &end!                                                            */
;*---------------------------------------------------------------------*/
(&end!)

