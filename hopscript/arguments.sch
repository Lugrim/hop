;*=====================================================================*/
;*    serrano/prgm/project/hop/hop/hopscript/arguments.sch             */
;*    -------------------------------------------------------------    */
;*    Author      :  Manuel Serrano                                    */
;*    Creation    :  Sat Dec  7 06:56:07 2019                          */
;*    Last change :  Sun Dec  8 06:25:45 2019 (serrano)                */
;*    Copyright   :  2019 Manuel Serrano                               */
;*    -------------------------------------------------------------    */
;*    Arguments macros for js2scheme                                   */
;*=====================================================================*/

;*---------------------------------------------------------------------*/
;*    js-arguments-vector-ref ...                                      */
;*---------------------------------------------------------------------*/
(define-macro (js-arguments-vector-ref vec arguments idx %this)
   `(if (and (>=fx ,idx 0) (<fx ,idx (vector-length ,vec)))
	(vector-ref-ur ,vec ,idx)
	(begin
	   (set! ,arguments (js-materialize-arguments ,%this ,vec ,arguments))
	   (js-arguments-ref ,arguments ,idx ,%this))))

;*---------------------------------------------------------------------*/
;*    js-arguments-vector-index-ref ...                                */
;*---------------------------------------------------------------------*/
(define-macro (js-arguments-vector-index-ref vec arguments idx %this)
   `(if (<u32 ,idx (fixnum->uint32 (vector-length ,vec)))
	(vector-ref-ur ,vec (uint32->fixnum ,idx))
	(begin
	   (set! ,arguments (js-materialize-arguments ,%this ,vec ,arguments))
	   (js-arguments-index-ref ,arguments ,idx ,%this))))

;*---------------------------------------------------------------------*/
;*    js-arguments-vector-set! ...                                     */
;*---------------------------------------------------------------------*/
(define-macro (js-arguments-vector-set! vec arguments idx val %this)
   `(if (and (>=fx ,idx 0) (<fx ,idx (vector-length ,vec)))
	(vector-set-ur! ,vec ,idx ,val)
	(begin
	   (set! ,arguments (js-materialize-arguments ,%this ,vec ,arguments))
	   (js-arguments-set! ,arguments ,idx ,val ,%this))))

;*---------------------------------------------------------------------*/
;*    js-arguments-vector-index-set! ...                               */
;*---------------------------------------------------------------------*/
(define-macro (js-arguments-vector-index-set! vec arguments idx val %this)
   `(if (<u32 ,idx (fixnum->uint32 (vector-length ,vec)))
	(vector-set-ur! ,vec (uint32->fixnum ,idx) ,val)
	(begin
	   (set! ,arguments (js-materialize-arguments ,%this ,vec ,arguments))
	   (js-arguments-index-set! ,arguments ,idx ,val ,%this))))