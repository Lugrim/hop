;*=====================================================================*/
;*    serrano/prgm/project/hop/hop/hopscript/profile.scm               */
;*    -------------------------------------------------------------    */
;*    Author      :  Manuel Serrano                                    */
;*    Creation    :  Tue Feb  6 17:28:45 2018                          */
;*    Last change :  Fri Jul  5 08:15:57 2024 (serrano)                */
;*    Copyright   :  2018-24 Manuel Serrano                            */
;*    -------------------------------------------------------------    */
;*    HopScript profiler.                                              */
;*=====================================================================*/

;*---------------------------------------------------------------------*/
;*    The module                                                       */
;*---------------------------------------------------------------------*/
(module __hopscript_profile

   (include "function.sch")
   
   (library hop)
   
   (cond-expand
      (profile
       (extern (export js-profile-allocs "bgl_js_profile_allocs"))))
   (cond-expand
      (profile
       (export js-profile-allocs::obj)))
   
   (extern ($js-profile-get-pcaches::pair-nil () "bgl_profile_get_pcaches"))

   (import __hopscript_types
	   __hopscript_property)

   (export (js-profile-init conf calltable symtable ::bstring)
	   (js-profile-snapshot source::bstring)
	   (js-profile-snapshot-add-listener! source::bstring ::procedure)
	   *profile-cache*
	   *profile-ctor*

	   (js-profile-register-pcache ::JsPropertyCache)
	   (js-profile-register-ctor ::vector)
	   
	   (js-profile-log-cache ::JsPropertyCache
	      #!key imap emap cmap pmap nmap amap vtable xmap)
	   (js-profile-log-index ::long)
	   
	   (js-profile-log-get ::obj loc)
	   (js-profile-log-put ::obj loc)
	   (js-profile-log-method ::obj point)

	   (js-profile-log-ctor ::JsFunction)
	   
	   (inline js-profile-log-call ::vector ::long)
	   (js-profile-log-funcall ::vector ::long ::obj ::obj)
	   (js-profile-log-cmap ::vector ::long ::obj)

	   (js-profile-log-method-function ::JsStringLiteral ::obj)
	   (js-profile-log-method-method ::JsStringLiteral ::obj)
	   
	   (log-cache-miss!)
	   (log-pmap-invalidation! ::obj)
	   (log-vtable! ::int ::vector ::vector)
	   (log-vtable-conflict!)
	   
	   (profile-hint ::obj ::symbol)
	   (profile-cache-index ::long)
	   (profile-cache-extension ::long)
	   (profile-vector-extension ::long ::long)))

;*---------------------------------------------------------------------*/
;*    *profile* ...                                                    */
;*---------------------------------------------------------------------*/
(define *profile* #f)
(define *profile-cache* #f)
(define *profile-ctor* #f)
(define *profile-caches* '())
(define *profile-gets* #l0)
(define *profile-gets-props* #f)
(define *profile-puts* #l0)
(define *profile-puts-props* #f)
(define *profile-methods* #l0)
(define *profile-methods-props* #f)
(define *profile-call-tables* '())

(define *profile-port* (current-error-port))

(define *profile-cache-hit*
   '(getCache getCachePrototype getCacheAccessor getCacheVtable
     putCache putCachePrototype putCacheAccessor utCacheVtable putCacheExtend
     callCacheVtable callCache))

(define *profile-cache-miss*
   '(getCacheMiss
     putCacheMiss
     callCacheMissUncachable))

(define *format-json-version* "0.0.1")
(define *format-pgo-version* "0.0.1")
(define *format-memviz-version* "0.0.1")

;*---------------------------------------------------------------------*/
;*    js-profile-init ...                                              */
;*---------------------------------------------------------------------*/
(define (js-profile-init conf calltable symtable trc)
   (unless *profile*
      (set! *profile* #t)
      (let ((trc (or (getenv "HOPTRACE") trc)))
	 (when (string-contains trc "hopscript")
	    (let ((m (pregexp-match "logfile=([^ ]+)" trc)))
	       (when m
		  (set! *profile-port* (open-output-file (cadr m)))))
	    (profile-cache-start! trc)
	    (when (string-contains trc "hopscript:pgo")
	       (set! trc (string-append "hopscript:cache hopscript:call hopscript:cmap format:pgo " trc)))
	    (when (string-contains trc "hopscript:cache")
	       (log-cache-miss!))
	    (when (string-contains trc "hopscript:function")
	       (log-function!))
	    (when (string-contains trc "hopscript:uncache")
	       (set! *profile-gets-props* '())
	       (set! *profile-puts-props* '())
	       (set! *profile-methods-props* '()))
	    (when (or (string-contains trc "hopscript:call")
		      (string-contains trc "hopscript:cmap"))
	       (when calltable
		  (set! *profile-call-tables*
		     (cons calltable *profile-call-tables*))))
	    (unless (string-contains trc "format:pgo")
	       (register-exit-function!
		  (lambda (n)
		     (with-handler
			(lambda (e)
			   (exception-notify e)
			   (exit -1))
			(begin
			   (profile-report-start trc conf)
			   (when (string-contains trc "hopscript:cache")
			      (profile-report-cache trc)
			      (display "," *profile-port*))
			   (when (string-contains trc "hopscript:hint")
			      (profile-hints trc))
			   (when (string-contains trc "hopscript:alloc")
			      (profile-allocs trc))
			   (when (string-contains trc "hopscript:call")
			      (profile-calls trc (or symtable '())))
			   (when (string-contains trc "hopscript:symtable")
			      (profile-symtable trc (or symtable '()) conf))
			   (when (string-contains trc "hopscript:cmap")
			      (profile-cmaps trc))
			   (profile-report-end trc conf)
			   (unless (eq? *profile-port* (current-error-port))
			      (close-output-port *profile-port*)))))))))))

;*---------------------------------------------------------------------*/
;*    profile-cache-start! ...                                         */
;*---------------------------------------------------------------------*/
(define (profile-cache-start! trc)
   (when (string-contains trc "hopscript:cache")
      (set! *profile-cache* #t))
   (when (string-contains trc "hopscript:ctor")
      (set! *profile-ctor* #t))
   (when (string-contains trc "hopscript:access")
      (set! *profile-cache* #t)
      (set! *profile-caches*
	 (map (lambda (k) (cons k '()))
	    (append *profile-cache-hit* *profile-cache-miss*)))))

;*---------------------------------------------------------------------*/
;*    snapshot-mutex ...                                               */
;*---------------------------------------------------------------------*/
(define snapshot-mutex (make-mutex))
(define snapshot-listeners '())

;*---------------------------------------------------------------------*/
;*    js-profile-snapshot ...                                          */
;*---------------------------------------------------------------------*/
(define (js-profile-snapshot source)
   (let ((path (hop-sofile-cache-path source :suffix ".prof")))
      (with-handler
	 (lambda (e)
	    (exception-notify e)
	    (when (file-exists? path)
	       (delete-path path)))
	 (synchronize snapshot-mutex
	    (let ((oport *profile-port*))
	       (make-directories (dirname path))
	       (call-with-output-file path
		  (lambda (port)
		     (unwind-protect
			(begin
			   (set! *profile-port* port)
			   (display "{\n\"format\": \"pgo\",\n" port)
			   (profile-report-cache
			      (format "srcfile=~a format:pgo" source))
			   (display ",\n" port)
			   (profile-report-ctor
			      (format "srcfile=~a format:pgo" source))
			   (display "}\n" port))
			(set! *profile-port* oport))))
	       (let ((ltn (assoc source snapshot-listeners)))
		  (when (pair? ltn)
		     ((cdr ltn) path))))))))

;*---------------------------------------------------------------------*/
;*    js-profile-snapshot-add-listener! ...                            */
;*---------------------------------------------------------------------*/
(define (js-profile-snapshot-add-listener! source proc)
   (set! snapshot-listeners (cons (cons source proc) snapshot-listeners)))

;*---------------------------------------------------------------------*/
;*    js-cache-table ...                                               */
;*---------------------------------------------------------------------*/
(define js-profile-lock (make-spinlock "js-profile-pcaches"))
(define js-profile-pcaches '())
(define js-profile-ctors '())

;*---------------------------------------------------------------------*/
;*    js-profile-register-pcache ...                                   */
;*---------------------------------------------------------------------*/
(define (js-profile-register-pcache pcache::JsPropertyCache)
   (when *profile-cache*
      (synchronize js-profile-lock
	 (set! js-profile-pcaches (cons pcache js-profile-pcaches)))))

;*---------------------------------------------------------------------*/
;*    js-profile-get-all-pcaches ...                                   */
;*---------------------------------------------------------------------*/
(define (js-profile-get-all-pcaches)
   (append js-profile-pcaches ($js-profile-get-pcaches)))

;*---------------------------------------------------------------------*/
;*    js-profile-register-ctor ...                                     */
;*---------------------------------------------------------------------*/
(define (js-profile-register-ctor ctor::vector)
   (synchronize js-profile-lock
      (set! js-profile-ctors (cons ctor js-profile-ctors))))

;*---------------------------------------------------------------------*/
;*    js-profile-log-cache ...                                         */
;*---------------------------------------------------------------------*/
(define (js-profile-log-cache cache::JsPropertyCache
	   #!key imap emap cmap pmap nmap amap xmap vtable)
   (with-access::JsPropertyCache cache (cntimap cntemap cntcmap cntpmap cntnmap cntamap cntvtable cntxmap)
      (when *profile-cache*
	 (cond
	    (imap (set! cntimap (+u32 #u32:1 cntimap)))
	    (emap (set! cntemap (+u32 #u32:1 cntemap)))
	    (cmap (set! cntcmap (+u32 #u32:1 cntcmap)))
	    (pmap (set! cntpmap (+u32 #u32:1 cntpmap)))
	    (nmap (set! cntnmap (+u32 #u32:1 cntnmap)))
	    (amap (set! cntamap (+u32 #u32:1 cntamap)))
	    (xmap (set! cntxmap (+u32 #u32:1 cntxmap)))
	    (vtable (set! cntvtable (+u32 #u32:1 cntvtable)))))))

;*---------------------------------------------------------------------*/
;*    js-profile-log-index ...                                         */
;*---------------------------------------------------------------------*/
(define (js-profile-log-index idx)
   (let* ((len (vector-length js-profile-accesses))
	  (i (if (>= idx len) (- len 1) idx)))
      (if (=fx idx -1)
	  (set! js-profile-dynamic-accesses
	     (+llong #l1 js-profile-dynamic-accesses))
	  (vector-set! js-profile-accesses i
	     (+llong #l1 (vector-ref js-profile-accesses i))))))

;*---------------------------------------------------------------------*/
;*    js-profile-log-get ...                                           */
;*---------------------------------------------------------------------*/
(define (js-profile-log-get prop loc)
   (set! *profile-gets* (+llong #l1 *profile-gets*))
   (when *profile-gets-props*
      (let ((c (assq prop *profile-gets-props*)))
	 (if (pair? c)
	     (set-cdr! c (+ 1 (cdr c)))
	     (set! *profile-gets-props* (cons (cons prop 1) *profile-gets-props*))))))
   
;*---------------------------------------------------------------------*/
;*    js-profile-log-put ...                                           */
;*---------------------------------------------------------------------*/
(define (js-profile-log-put prop loc)
   (set! *profile-puts* (+llong #l1 *profile-puts*))
   (when *profile-puts-props*
      (let ((c (assq prop *profile-puts-props*)))
	 (if (pair? c)
	     (set-cdr! c (+ 1 (cdr c)))
	     (set! *profile-puts-props* (cons (cons prop 1) *profile-puts-props*))))))
   
;*---------------------------------------------------------------------*/
;*    js-profile-log-method ...                                        */
;*---------------------------------------------------------------------*/
(define (js-profile-log-method prop point)
   (set! *profile-methods* (+llong #l1 *profile-methods*))
   (when *profile-methods-props*
      (let ((c (assq prop *profile-methods-props*)))
	 (if (pair? c)
	     (set-cdr! c (+ 1 (cdr c)))
	     (set! *profile-methods-props* (cons (cons prop 1) *profile-methods-props*))))))

;*---------------------------------------------------------------------*/
;*    js-profile-log-ctor ...                                          */
;*---------------------------------------------------------------------*/
(define (js-profile-log-ctor ctor::JsFunction)
   (when *profile-ctor*
      (with-access::JsFunction ctor (info constrsize)
	 (when (<fx (js-function-info-constrsize info) 0)
	    (js-profile-register-ctor info))
	 (js-function-info-constrsize-set! info constrsize))))

;*---------------------------------------------------------------------*/
;*    js-profile-log-call ...                                          */
;*---------------------------------------------------------------------*/
(define-inline (js-profile-log-call table idx)
   (vector-set! table idx (+llong (vector-ref table idx) #l1)))

;*---------------------------------------------------------------------*/
;*    js-profile-log-funcall ...                                       */
;*---------------------------------------------------------------------*/
(define (js-profile-log-funcall table idx fun source)
   (when (js-function? fun)
      (with-access::JsFunction fun (info)
	 (let ((src (vector-ref info 3)))
	    (when (and (string? src) (string=? src source))
	       (let* ((id (vector-ref info 4))
		      (bucket (vector-ref table idx)))
		  (if (pair? bucket)
		      (let ((c (assq id bucket)))
			 (if (pair? c)
			     (set-cdr! c (+llong (cdr c) #l1))
			     (vector-set! table idx (cons (cons id #l1) bucket))))
		      (vector-set! table idx (list (cons id #l1))))))))))

;*---------------------------------------------------------------------*/
;*    js-profile-log-cmap ...                                          */
;*---------------------------------------------------------------------*/
(define (js-profile-log-cmap table idx obj)
   (when (js-object? obj)
      (with-access::JsObject obj (cmap)
	 (let ((bucket (vector-ref table idx)))
	    (if (pair? bucket)
		(let ((c (assq cmap bucket)))
		   (if (pair? c)
		       (set-cdr! c (+llong (cdr c) #l1))
		       (vector-set! table idx (cons (cons cmap #l1) bucket))))
		(vector-set! table idx (list (cons cmap #l1))))))))

;*---------------------------------------------------------------------*/
;*    js-profile-log-method-method ...                                 */
;*---------------------------------------------------------------------*/
(define (js-profile-log-method-method name loc)
   ;; (tprint "METHOD " name)
   #f)

;*---------------------------------------------------------------------*/
;*    js-profile-log-method-function ...                               */
;*---------------------------------------------------------------------*/
(define (js-profile-log-method-function name loc)
   ;; (tprint "FUNCTION " name)
   #f)

;*---------------------------------------------------------------------*/
;*    *misses* ...                                                     */
;*---------------------------------------------------------------------*/
(define *misses* '())
(define *log-misses* #f)
(define *log-miss-threshold* 100)
(define *log-pmap-invalidate* #f)
(define *log-vtables* #f)

(define *pmap-invalidations* 0)
(define *vtables* '())
(define *vtables-cnt* 0)
(define *vtables-mem* 0)
(define *vtables-conflicts* 0)

;*---------------------------------------------------------------------*/
;*    log-cache-miss! ...                                              */
;*---------------------------------------------------------------------*/
(define (log-cache-miss!)
   (set! *log-misses* #t)
   (set! *log-pmap-invalidate* #t)
   (set! *log-vtables* #t))

;*---------------------------------------------------------------------*/
;*    ->llong ...                                                      */
;*---------------------------------------------------------------------*/
(define (->llong::llong n)
   (cond
      ((fixnum? n) (fixnum->llong n))
      ((uint32? n) (uint32->llong n))
      ((flonum? n) (flonum->llong n))
      ((elong? n) (elong->llong n))
      ((flonum? n) (flonum->llong n))
      ((llong? n) n)
      (else #l0)))

;*---------------------------------------------------------------------*/
;*    ->flonum ...                                                     */
;*---------------------------------------------------------------------*/
(define (->flonum::double n)
   (cond
      ((fixnum? n) (fixnum->flonum n))
      ((uint32? n) (uint32->flonum n))
      ((flonum? n) n)
      ((elong? n) (elong->flonum n))
      ((llong? n) (llong->flonum n))
      (else 0.0)))

;*---------------------------------------------------------------------*/
;*    percent ...                                                      */
;*---------------------------------------------------------------------*/
(define (percent x y)
   (inexact->exact
      (floor (*fl 100.0 (/fl (->flonum x) (->flonum y))))))

;*---------------------------------------------------------------------*/
;*    padding ...                                                      */
;*---------------------------------------------------------------------*/
(define (padding o sz #!optional (align 'left))

   (define (/int a b)
      (let ((r (/ a b)))
	 (if (flonum? r)
	     (inexact->exact (round r))
	     r)))
   
   (define (format-number o)
      (let ((s (number->string o)))
	 (cond
	    ((and (<= (string-length s) sz) (<= o 10000))
	     s)
	    ;; ((< o 1000)
	    ;;  (number->string o))
	    ;; ((< o 1000000)
	    ;;  (string-append (number->string (/int o 1000)) ".10^3"))
	    ;; ((< o 1000000000)
	    ;;  (string-append (number->string (/int o 1000000)) ".10^6"))
	    (else
	     s))))

   (define (format-uint32 o)
      (let ((s (number->string o)))
	 (cond
	    ((and (<= (string-length s) sz) (<u32 o #u32:10000))
	     s)
	    ;; ((<u32 o #u32:1000)
	    ;;  (number->string o))
	    ;; ((<u32 o #u32:1000000)
	    ;;  (string-append (number->string (/u32 o #u32:1000)) ".10^3"))
	    ;; ((<u32 o #u32:1000000000)
	    ;;  (string-append (number->string (/u32 o #u32:1000000)) ".10^6"))
	    (else
	     s))))

   (define (format-llong o)
      (let ((s (number->string o)))
	 (cond
	    ((and (<= (string-length s) sz) (<llong o #l10000))
	     s)
	    ;; ((<llong o #l1000)
	    ;;  (number->string o))
	    ;; ((<llong o #l1000000)
	    ;;  (string-append (number->string (/llong o #l1000)) ".10^3"))
	    ;; ((<llong o #l1000000000)
	    ;;  (string-append (number->string (/llong o #l1000000)) ".10^6"))
	    ;; ((<llong o #l1000000000000)
	    ;;  (string-append (number->string (/llong o #l1000000000)) ".10^9"))
	    (else
	     s))))

   (let* ((s (cond
		((string? o) o)
		((uint32? o) (format-uint32 o))
		((llong? o) (format-llong o))
		((number? o) (format-number o))
		((symbol? o) (symbol->string o))
		((eq? o (class-nil JsStringLiteralASCII)) "")
		(else (call-with-output-string (lambda (p) (display o p))))))
	  (l (string-length s)))
      (if (> l sz)
          (substring s 0 sz)
          (case align
             ((left)
              (string-append s (make-string (- sz l) #\space)))
             ((right)
              (string-append (make-string (- sz l) #\space) s))
             (else
              (let ((res (make-string sz #\space)))
                 (blit-string! s 0 res (/fx (-fx sz l) 2) l)
                 res))))))

;*---------------------------------------------------------------------*/
;*    js-symbol->string! ...                                           */
;*---------------------------------------------------------------------*/
(define (js-symbol->string! s)
   (cond
      ((symbol? s)
       (symbol->string! s))
      ((isa? s JsSymbolLiteral)
       (with-access::JsSymbolLiteral s (val)
	  val))
      (else
       (typeof s))))

;*---------------------------------------------------------------------*/
;*    *functions* ...                                                  */
;*---------------------------------------------------------------------*/
(define *functions* '())
(define *log-functions* #f)
(define *function-threshold* 10)

;*---------------------------------------------------------------------*/
;*    log-function! ...                                                */
;*---------------------------------------------------------------------*/
(define (log-function!)
   (set! *log-functions* #t))

;*---------------------------------------------------------------------*/
;*    log-pmap-invalidation! ...                                       */
;*---------------------------------------------------------------------*/
(define (log-pmap-invalidation! reason)
   ;;(tprint "invalide " reason)
   (set! *pmap-invalidations* (+ 1 *pmap-invalidations*)))

;*---------------------------------------------------------------------*/
;*    log-vtable! ...                                                  */
;*---------------------------------------------------------------------*/
(define (log-vtable! idx vtable old)
   (when *log-vtables*
      (set! *vtables-cnt* (+ 1 *vtables-cnt*))
      ;; add 3 for the vector header
      (set! *vtables-mem* (+ *vtables-mem* (+ 3 (vector-length vtable))))
      (set! *vtables* (cons vtable (remq! old *vtables*)))))

;*---------------------------------------------------------------------*/
;*    log-vtable-conflict! ...                                         */
;*---------------------------------------------------------------------*/
(define (log-vtable-conflict!)
   (when *log-vtables*
      (set! *vtables-conflicts* (+fx 1 *vtables-conflicts*))))

;*---------------------------------------------------------------------*/
;*    attr->index ...                                                  */
;*---------------------------------------------------------------------*/
(define (attr->index attr)
   (case attr
      ((hint) 0)
      ((nohint) 1)
      ((dispatch) 2)
      ((type) 3)
      ((notype) 4)
      (else (error "profile-hint" "illegal attr" attr))))

;*---------------------------------------------------------------------*/
;*    profile-hint ...                                                 */
;*---------------------------------------------------------------------*/
(define (profile-hint name attr)
   (when *log-functions*
      (let ((o (assq name *functions*))
	    (i (attr->index attr)))
	 (if (not o)
	     (let ((vec (make-vector (+fx 1 (attr->index 'notype)) 0)))
		(vector-set! vec i 1)
		(set! *functions* (cons (cons name (cons -1 vec)) *functions*)))
	     (vector-set! (cddr o) i (+fx 1 (vector-ref (cddr o) i)))))))

;*---------------------------------------------------------------------*/
;*    profile-hints ...                                                */
;*---------------------------------------------------------------------*/
(define (profile-hints trc)

   (define (show-json-hints)
      (with-output-to-port *profile-port*
	 (lambda ()
	    (let ((m (pregexp-match "hopscript:function([0-9]+)" trc)))
	       (when m
		  (set! *function-threshold* (string->integer (cadr m)))))
	    (for-each (lambda (e)
			 (set-car! (cdr e) (apply + (vector->list (cddr e)))))
	       *functions*)
	    (print "\"functions\": {")
	    (print "  \"functionNumber\": " (length *functions*) ",")
	    (print "  \"calls\": {")
	    (print "    \"hinted\": "
	       (let ((i (attr->index 'hint)))
		  (apply + (map (lambda (e) (vector-ref (cddr e) i)) *functions*)))
	       ",")
	    (print "    \"unhinted\": "
	       (let ((i (attr->index 'nohint)))
		  (apply + (map (lambda (e) (vector-ref (cddr e) i)) *functions*)))
	       ",")
	    (print "    \"dispatch\": "
	       (let ((i (attr->index 'dispatch)))
		  (apply + (map (lambda (e) (vector-ref (cddr e) i)) *functions*)))
	       
	       ",")
	    (print "    \"typed\": " 
	       (let ((i (attr->index 'type)))
		  (apply + (map (lambda (e) (vector-ref (cddr e) i)) *functions*)))
	       ",")
	    (print "    \"untyped\": "
	       (let ((i (attr->index 'notype)))
		  (apply + (map (lambda (e) (vector-ref (cddr e) i)) *functions*)))
	       "\n  }\n},"))))
   
   (define (show-text-hints)
      (with-output-to-port *profile-port*
	 (lambda ()
	    (let ((m (pregexp-match "hopscript:function([0-9]+)" trc)))
	       (when m
		  (set! *function-threshold* (string->integer (cadr m)))))
	    (for-each (lambda (e)
			 (set-car! (cdr e) (apply + (vector->list (cddr e)))))
	       *functions*)
	    (print  "\nFUNCTIONS:\n" "==========\n")
	    (print "total number of functions: "
	       (length *functions*))
	    (print "  total function hinted calls  : "
	       (let ((i (attr->index 'hint)))
		  (apply + (map (lambda (e) (vector-ref (cddr e) i)) *functions*))))
	    (print "  total function unhinted calls: "
	       (let ((i (attr->index 'nohint)))
		  (apply + (map (lambda (e) (vector-ref (cddr e) i)) *functions*))))
	    (print "  total function dispatch calls : "
	       (let ((i (attr->index 'dispatch)))
		  (apply + (map (lambda (e) (vector-ref (cddr e) i)) *functions*))))
	    (print "  total function typed calls   : " 
	       (let ((i (attr->index 'type)))
		  (apply + (map (lambda (e) (vector-ref (cddr e) i)) *functions*))))
	    (print "  total function untyped calls : "
	       (let ((i (attr->index 'notype)))
		  (apply + (map (lambda (e) (vector-ref (cddr e) i)) *functions*))))
	    (newline)
	    (print ";; function: hint/nohint/dispatch/type/notype")
	    (for-each (lambda (e)
			 (when (>= (cadr e) *function-threshold*)
			    (print (car e) ": "
			       (format "~(/)" (vector->list (cddr e))))))
	       (sort (lambda (e1 e2)
			(cond
			   ((> (cadr e1) (cadr e2)) #t)
			   ((< (cadr e1) (cadr e2)) #f)
			   (else (string<=? (car e1) (car e2)))))
		  *functions*))
	    (newline))))
   
   (if (string-contains trc "format:json")
       (show-json-hints)
       (show-text-hints)))

;*---------------------------------------------------------------------*/
;*    profiling                                                        */
;*---------------------------------------------------------------------*/
(define js-profile-allocs (make-vector 32 #l0))
(define js-profile-accesses (make-vector 32 #l0))
(define js-profile-extensions (make-vector 32 #l0))
(define js-profile-vectors (make-vector 256 #l0))
(define js-profile-vector-maxlen 0)
(define js-profile-dynamic-accesses #l0)

;*---------------------------------------------------------------------*/
;*    profile-allocs ...                                               */
;*---------------------------------------------------------------------*/
(define (profile-allocs trc)
   
   (define (show-json-percentages vec)
      (let ((len (vector-length vec)))
	 (display " [")
	 (let loop ((i (-fx len 1))
		    (sum #l0))
	    (if (=fx i -1)
		(let luup ((i 0)
			   (cum #l0)
			   (sep "\n"))
		   (when (and (<fx i len) (<llong cum sum))
		      (display sep)
		      (let* ((n0 (vector-ref vec i))
			     (n (if (fixnum? n0) (fixnum->llong n0) n0))
			     (c (+llong cum n))
			     (p (/llong (*llong n (fixnum->llong 100)) sum))
			     (pc (/llong (*llong c (fixnum->llong 100)) sum)))
			 (printf "   {\"idx\": ~d, \"occ\": ~d, \"per\": ~2,0d, \"cumul\": ~d}" i n p pc)
			 (luup (+fx i 1) c ",\n"))))
		(let ((n (vector-ref vec i)))
		   (loop (-fx i 1)
		      (+llong sum (if (fixnum? n) (fixnum->llong n) n))))))
	 (display "]")))

   (define (show-text-percentages vec)
      (let ((len (vector-length vec)))
	 (let loop ((i (-fx len 1))
		    (sum #l0))
	    (if (=fx i -1)
		(let luup ((i 0)
			   (cum #l0))
		   (when (and (<fx i len) (<llong cum sum))
		      (let* ((n0 (vector-ref vec i))
			     (n (if (fixnum? n0) (fixnum->llong n0) n0))
			     (c (+llong cum n))
			     (p (/llong (*llong n (fixnum->llong 100)) sum))
			     (pc (/llong (*llong c (fixnum->llong 100)) sum)))
			 (printf "  ~a: ~10d (~2,0d%) -> ~d%\n"
			    (if (=fx i (-fx len 1))
				"rest"
				(format "~4d" i))
			    n p pc)
			 (luup (+fx i 1) c))))
		(let ((n (vector-ref vec i)))
		   (loop (-fx i 1)
		      (+llong sum (if (fixnum? n) (fixnum->llong n) n))))))))

   (define (show-json-alloc)
      (cond-expand
	 (profile
	  (print "\"allocs\": {")
	  (display " \"objectAllocs\":")
	  (show-json-percentages js-profile-allocs)
	  (display ",\n \"accesses\":")
	  (show-json-percentages js-profile-accesses)
	  (display ",\n \"extensions\":")
	  (show-json-percentages js-profile-extensions)
	  (display ",\n \"vectorExtensions\":")
	  (show-json-percentages js-profile-vectors)
	  (print "\n},"))
	 (else
	  (error "hop" "no alloc profiling configured" #f))))
				  
   (define (show-text-alloc)
      (cond-expand
	 (profile
	  (print  "\nOBJECT ALLOCS:\n" "==============\n")
	  (show-text-percentages js-profile-allocs)
	  (print  "\nACCESSES:\n" "=========\n")
	  (show-text-percentages js-profile-accesses)
	  (print  "\nEXTENSIONS:\n" "===========\n")
	  (show-text-percentages js-profile-extensions)
	  (print  "\nVECTOR EXTENSIONS:\n" "==================\n")
	  (print "max-extension: " js-profile-vector-maxlen "\n")
	  (show-text-percentages js-profile-vectors))
	 (else
	  (error "hop" "no alloc profiling configured" #f))))

   (with-output-to-port *profile-port*
      (lambda ()
	 (let ((m (pregexp-match "hopscript:alloc([0-9]*)" trc)))
	    (cond-expand
	       (profile
		(if (string-contains trc "format:json")
		    (show-json-alloc)
		    (show-text-alloc)))
	       (else
		(print "Allocation profiling disabled (re-configure Hop with \"--profile\")")))))))

;*---------------------------------------------------------------------*/
;*    profile-cache-index ...                                          */
;*---------------------------------------------------------------------*/
(define (profile-cache-index idx)
   (cond-expand
      (profile
       (let* ((len (vector-length js-profile-accesses))
	      (i (if (>= idx len) (- len 1) idx)))
	  (vector-set! js-profile-accesses i
	     (+llong (fixnum->llong 1) (vector-ref js-profile-accesses i)))))
      (else
       #f)))

;*---------------------------------------------------------------------*/
;*    profile-cache-extension ...                                      */
;*---------------------------------------------------------------------*/
(define (profile-cache-extension idx)
   (cond-expand
      (profile
       (let* ((len (vector-length js-profile-extensions))
	      (i (if (>= idx len) (- len 1) idx)))
	  (vector-set! js-profile-extensions i
	     (+llong (fixnum->llong 1) (vector-ref js-profile-extensions i)))))
      (else
       #f)))

;*---------------------------------------------------------------------*/
;*    profile-vector-extension ...                                     */
;*---------------------------------------------------------------------*/
(define (profile-vector-extension nlen olen)
   (cond-expand
      (profile
       (let* ((len (vector-length js-profile-vectors))
	      (i (if (>= olen len) (- len 1) olen)))
	  (when (>fx nlen js-profile-vector-maxlen)
	     (set! js-profile-vector-maxlen nlen))
	  (vector-set! js-profile-vectors i
	     (+llong (fixnum->llong 1) (vector-ref js-profile-vectors i)))))
      (else
       #f)))
   
;*---------------------------------------------------------------------*/
;*    profile-report-start ...                                         */
;*---------------------------------------------------------------------*/
(define (profile-report-start trc conf)
   (with-output-to-port *profile-port*
      (lambda ()
	 (cond
	    ((string-contains trc "format:json")
	     (print "{\n\"format\": \"json\",")
	     (printf "\"version\": \"~a\",\n" *format-json-version*))
	    ((string-contains trc "format:pgo")
	     (print "{\n\"format\": \"pgo\",")
	     (printf "\"version\": \"~a\",\n" *format-pgo-version*))
	    ((string-contains trc "format:memviz")
	     (print "{\n\"format\": \"memviz\",")
	     (printf "\"version\": \"~a\",\n" *format-memviz-version*))))))

;*---------------------------------------------------------------------*/
;*    profile-report-end ...                                           */
;*---------------------------------------------------------------------*/
(define (profile-report-end trc conf)
   (when (or (string-contains trc "format:json")
	     (string-contains trc "format:pgo")
	     (string-contains trc "format:memviz"))
      (with-output-to-port *profile-port*
	 (lambda ()
	    (display "\"config\": ")
	    (profile-config conf)
	    (display ",\n" )
	    (display "\"run\": {\n")
	    (printf "  \"HOPTRACE\": ~s,\n" (getenv "HOPTRACE"))
	    (printf "  \"commandline\": \"~( )\",\n" (command-line))
	    (printf "  \"date\": ~s\n  }\n}\n" (date))))))

;*---------------------------------------------------------------------*/
;*    profile-config ...                                               */
;*---------------------------------------------------------------------*/
(define (profile-config conf)
   (display "{\n")
   (when (pair? conf)
      (let loop ((conf conf))
	 (let ((v (cadr conf)))
	    (printf "  \"~a\": ~a" (keyword->string (car conf))
	       (cond
		  ((boolean? v) (if v "true" "false"))
		  ((string? v) (string-append "\"" v "\""))
		  (else v)))
	    (when (pair? (cddr conf))
	       (display ",\n")
	       (loop (cddr conf))))))
   (display "\n}"))

;*---------------------------------------------------------------------*/
;*    vector-mem-size ...                                              */
;*    -------------------------------------------------------------    */
;*    An approximation of a vector memory size                         */
;*---------------------------------------------------------------------*/
(define (vector-mem-size v)
   (*fx v (if (>fx (bigloo-config 'elong-size) 32) 8 4)))

;*---------------------------------------------------------------------*/
;*    profile-report-cache ...                                         */
;*---------------------------------------------------------------------*/
(define (profile-report-cache trc)
   
   (define (hit? e) (memq e *profile-cache-hit*))
   (define (hit0? e) (memq e '(getCache putCache callCache)))
   (define (miss? e) (memq e *profile-cache-miss*))
   
   (define (vfor-each proc::procedure vec::vector)
      (let loop ((i (-fx (vector-length vec) 1)))
	 (when (>=fx i 0)
	    (proc i (vector-ref vec i))
	    (loop (-fx i 1)))))

   (define (vfilter pred::procedure vec::vector)
      (let ((res '()))
	 (vfor-each (lambda (i pc)
		       (when (pred pc)
			  (set! res (cons pc res))))
	    vec)
	 (reverse! res)))

   (define (vmap proc::procedure vec::vector)
      (vector->list (vector-map proc vec)))

   (define (vany proc::procedure vec::vector)
      (let loop ((i (-fx (vector-length vec) 1)))
	 (when (>=fx i 0)
	    (if (proc (vector-ref vec i))
		(vector-ref vec i)
		(loop (-fx i 1))))))

   (define filecaches
      (let ((m (pregexp-match "srcfile=([^ ]+)" trc)))
	 (if m
	     (let ((filename (cadr m)))
		(filter (lambda (pc)
			   (with-access::JsPropertyCache pc (src)
			      (string=? src filename)))
		   (js-profile-get-all-pcaches)))
	     (js-profile-get-all-pcaches))))

   (define threshold
      (let ((m (pregexp-match "hopscript:cache=([0-9]+)" trc)))
	 (if m (string->integer (cadr m)) 100)))

   (define (pcache-hits::llong pc)
      (with-access::JsPropertyCache pc (cntimap cntemap cntcmap cntpmap cntnmap cntamap cntxmap cntvtable)
	 (+llong (uint32->llong cntimap)
	    (+llong (uint32->llong cntemap)
	       (+llong (uint32->llong cntcmap)
		  (+llong (uint32->llong cntpmap)
		     (+llong (uint32->llong cntnmap)
			(+llong (uint32->llong cntamap)
			   (+llong (uint32->llong cntxmap)
			      (uint32->llong cntvtable))))))))))

   (define (pcache-multi pc)
      (with-access::JsPropertyCache pc (name cntimap cntemap cntcmap cntpmap cntnmap cntamap cntxmap cntvtable)
	 (when (> (+ (if (>u32 cntimap 0) 1 0)
		     (if (>u32 cntemap 0) 1 0)
		     (if (>u32 cntcmap 0) 1 0)
		     (if (>u32 cntpmap 0) 1 0)
		     (if (>u32 cntnmap 0) 1 0)
		     (if (>u32 cntamap 0) 1 0)
		     (if (>u32 cntxmap 0) 1 0)
		     (if (>u32 cntvtable 0) 1 0))
		  1)
	    (cons name (pcache-hits pc)))))

   (define (filecache-sum-field::llong filecaches fieldname)

      (let ((field (find-class-field JsPropertyCache fieldname)))
         (if field
             (let ((proc (class-field-accessor field)))
                (apply +llong-va
                   (map (lambda (fc)
			   (->llong (proc fc)))
                      filecaches)))
             (error "filecache-sum-field" "cannot find field" fieldname))))

   (define (+llong-va . l)
      (cond
	 ((null? l)
	  #l0)
	 ((null? (cdr l))
	  (car l))
	 (else
	  (let loop ((acc (car l))
		     (l (cdr l)))
	     (if (null? l)
		 acc
		 (loop (+llong (car l) acc) (cdr l)))))))
   
   (define (filecaches-hits::llong filecaches)
      (apply +llong-va
	 (map pcache-hits filecaches)))

   (define (filecaches-misses filecaches)
      (filecache-sum-field filecaches 'cntmiss))

   (define (filecaches-cmaps filecaches)
      (filecache-sum-field filecaches 'cntcmap))

   (define (filecaches-imaps filecaches)
      (filecache-sum-field filecaches 'cntimap))

   (define (filecaches-emaps filecaches)
      (filecache-sum-field filecaches 'cntemap))

   (define (filecaches-pmaps filecaches)
      (filecache-sum-field filecaches 'cntpmap))

   (define (filecaches-nmaps filecaches)
      (filecache-sum-field filecaches 'cntnmap))

   (define (filecaches-amaps filecaches)
      (filecache-sum-field filecaches 'cntamap))

   (define (filecaches-xmaps filecaches)
      (filecache-sum-field filecaches 'cntxmap))

   (define (filecaches-vtables filecaches)
      (filecache-sum-field filecaches 'cntvtable))

   (define (filecaches-multis filecaches)
      (filter-map (lambda (fc)
		     (pcache-multi fc))
	 filecaches))

   (define (filecaches-usage-filter filecaches u)
      (filter (lambda (pc)
		 (with-access::JsPropertyCache pc (usage)
		    (eq? u usage)))
	 filecaches))

   (define (total-uncaches::llong)
      (+llong *profile-gets* *profile-puts*))

   (define total
      (let ((h1 (filecaches-hits filecaches))
	    (m1 (filecaches-misses filecaches))
	    (u1 (total-uncaches)))
	 (+llong h1 (+llong m1 u1))))

   (define multi
      (filecaches-multis filecaches))

   (define (max-vtable-entries)
      (if (null? *vtables*)
	  (values 0 0)
	  (let* ((msize (apply max (map vector-length *vtables*)))
		 (vec (make-vector msize 0)))
	     (for-each (lambda (vtable)
			  (vfor-each (lambda (i v)
					(unless (eq? v #unspecified)
					   (vector-set! vec i
					      (+fx (vector-ref vec i) 1))))
			     vtable))
		*vtables*)
	     (let ((locations 0)
		   (degree 0))
		(vfor-each (lambda (i v)
			      (when (>fx v 0)
				 (set! locations (+fx locations 1))
				 (when (>fx v degree)
				    (set! degree v))))
		   vec)
		(values locations degree)))))

   (define (show-json-property-cache-entries filecaches fieldname)
      (let* ((field (find-class-field JsPropertyCache fieldname))
	     (proc (class-field-accessor field)))
	 (let ((table '()))
	    (for-each (lambda (pc)
			 (with-access::JsPropertyCache pc (name)
			    (when (> (proc pc) 0)
			       (let ((old (assq name table)))
				  (if (not old)
				      (set! table (cons (cons name (proc pc)) table))
				      (set-cdr! old (+ (cdr old) (proc pc))))))))
	       filecaches)
	    (for-each (lambda (e)
			 (when (> (cdr e) *log-miss-threshold*)
			    (print "        { \"" (car e) "\": " (cdr e) " }, ")))
	       (sort (lambda (x y)
			(cond
			   ((> (cdr x) (cdr y)) #t)
			   ((< (cdr x) (cdr y)) #f)
			   (else (string<=? (js-symbol->string! (car x))
				    (js-symbol->string! (car y))))))
		  table)))))

   (define (show-json-cache map)
      (let ((k (symbol-append 'cnt map)))
	 (print "  \"" map "\": {")
	 (print "    \"get\": {")
	 (print "      \"total\": " (filecache-sum-field (filecaches-usage-filter filecaches 'get) k) ",")
	 (print "      \"entries\": [")
	 (show-json-property-cache-entries (filecaches-usage-filter filecaches 'get) k)
	 (print "        -1 ]")
	 (print "    },")
	 (print "    \"put\": {")
	 (print "      \"total\": " (filecache-sum-field (filecaches-usage-filter filecaches 'put) k) ",")
	 (print "      \"entries\": [")
	 (show-json-property-cache-entries (filecaches-usage-filter filecaches 'put) k)
	 (print "        -1 ]")
	 (print "    },")
	 (print "    \"call\": {")
	 (print "      \"total\": " (filecache-sum-field (filecaches-usage-filter filecaches 'call) k) ",")
	 (print "      \"entries\": [")
	 (show-json-property-cache-entries (filecaches-usage-filter filecaches 'call) k)
	 (print "        -1 ]")
	 (print "    }")
	 (print "  },")))

   (define (show-pgo-pcaches fc::vector)
      (let ((vpc (collapse
		    (sort (lambda (x y)
			     (with-access::JsPropertyCache x ((xpoint point))
				(with-access::JsPropertyCache y ((ypoint point))
				   (<= xpoint ypoint))))
		       fc))))
	 (vfor-each (lambda (i pc)
		       (with-access::JsPropertyCache pc (point usage cntmiss cntimap cntemap cntcmap cntpmap cntnmap cntamap cntxmap cntvtable)
			  (when (or (> (pcache-hits pc) 0) (> cntmiss *log-miss-threshold*))
			     (display* "      { \"point\": " point)
			     (display* ", \"usage\": \"" usage "\"")
			     (when (> cntmiss 1) (display* ", \"miss\": " cntmiss))
			     (when (> cntimap 0) (display* ", \"imap\": " cntimap))
			     (when (> cntemap 0) (display* ", \"emap\": " cntemap))
			     (when (> cntcmap 0) (display* ", \"cmap\": " cntcmap))
			     (when (> cntpmap 0) (display* ", \"pmap\": " cntpmap))
			     (when (> cntnmap 0) (display* ", \"nmap\": " cntnmap))
			     (when (> cntamap 0) (display* ", \"amap\": " cntamap))
			     (when (> cntxmap 0) (display* ", \"xmap\": " cntxmap))
			     (when (> cntvtable 0) (display* ", \"vtable\": " cntvtable))
			     (if (>fx i 0)
				 (print " }, ")
				 (print " } ")))))
	    vpc)))

   (define (collapse vec)
      (let ((len (vector-length vec)))
	 (if (>fx len 1)
	     (let loop ((i 1)
			(old (vector-ref vec 0))
			(res '()))
		(if (=fx i len)
		    (list->vector (cons old res))
		    (let ((x (vector-ref vec i)))
		       (with-access::JsPropertyCache x ((xpoint point)
							(xusage usage)
							(xcntmiss cntmiss)
							(xcntimap cntimap)
							(xcntemap cntemap)
							(xcntcmap cntcmap)
							(xcntpmap cntpmap)
							(xcntnmap cntnmap)
							(xcntamap cntamap)
							(xcntxmap cntxmap)
							(xcntvtable cntvtable))
			  (with-access::JsPropertyCache old (point usage cntmiss cntimap cntemap cntcmap cntpmap cntnmap cntamap cntxmap cntvtable)
			     (if (and (= point xpoint) (eq? xusage usage))
				 (begin
				    (set! cntmiss (+u32 cntmiss xcntmiss))
				    (set! cntimap (+u32 cntimap xcntimap))
				    (set! cntemap (+u32 cntemap xcntemap))
				    (set! cntcmap (+u32 cntcmap xcntcmap))
				    (set! cntpmap (+u32 cntpmap xcntpmap))
				    (set! cntnmap (+u32 cntnmap xcntnmap))
				    (set! cntamap (+u32 cntamap xcntamap))
				    (set! cntxmap (+u32 cntxmap xcntxmap))
				    (set! cntvtable (+u32 cntvtable xcntvtable))
				    (loop (+fx i 1) old res))
				 (loop (+fx i 1) x (cons old res))))))))
	     vec)))

   (cond
      ((string-contains trc "format:pgo")
       (when (pair? filecaches)
	  (with-output-to-port *profile-port*
	     (lambda ()
		(print "\"caches\": [")
		(let ((srcs (delete-duplicates!
			       (map (lambda (pc)
				       (with-access::JsPropertyCache pc (src) src))
				  filecaches))))
		   (for-each (lambda (s)
				(let ((pcs (filter (lambda (pc)
						      (with-access::JsPropertyCache pc (src cntmiss)
							 (and (string=? src s)
							      (or (or (> (pcache-hits pc) 0)
								      (> cntmiss *log-miss-threshold*))))))
					      filecaches)))
				   (when (pair? pcs)
				      (print "  { \"filename\": \"" s "\",")
				      (print "    \"caches\": [")
				      (show-pgo-pcaches (list->vector pcs))
				      (print "   ] },"))))
		      srcs))
		(print "  { \"filename\": \"\", \"caches\": [] }")
		(display "]")))))
      ((string-contains trc "format:json")
       (with-output-to-port *profile-port*
	  (lambda ()
	     (multiple-value-bind (locations degree)
		(max-vtable-entries)
		(print "\"format\": \"json\",")
		(print "\"caches\": {")
		(print "  \"accesses\": " total ",")
		(print "  \"hits\": " (filecaches-hits filecaches) ",")
		(print "  \"misses\": " (filecaches-misses filecaches) ",")
		(print "  \"multis\": " (apply + (map cdr multi)) ",")
		(print "  \"uncaches\": {")
		(print "    \"total\": " (total-uncaches) ",")
		(print "    \"get\": " *profile-gets* ",")
		(print "    \"put\": " *profile-puts* ",")
		(print "    \"call\": " *profile-methods*)
		(print "  },")
		(show-json-cache 'imap)
		(show-json-cache 'emap)
		(show-json-cache 'cmap)
		(show-json-cache 'pmap)
		(show-json-cache 'amap)
		(show-json-cache 'vtable)
		(print "  \"hclasses\": " (gencmapid) ",")
		(print "  \"invalidations\": " *pmap-invalidations* ",")
		(print "  \"vtables\": { \"number\": " *vtables-cnt* ", \"mem\": " (vector-mem-size *vtables-mem*) ", \"locations\": " locations ", \"degree\":" degree ", \"conflicts\":" *vtables-conflicts* "}")
		(print "}")))))
      (else
       (fprint *profile-port* "\nCACHES:\n" "=======")
       (fprintf *profile-port* "~(, )\n\n" trc)
       (for-each (lambda (what)
		    (let ((c 0))
		       (fprint *profile-port* (car what) ": "
			  (cadr what))
		       (for-each (lambda (e)
				    (when (or (>= (cdr e) *log-miss-threshold*)
					      (< c 10))
				       (set! c (+ c 1))
				       (fprint *profile-port* "   "
					  (car e) ": " (cdr e))))
			  (sort (lambda (e1 e2)
				   (cond
				      ((> (cdr e1) (cdr e2)) #t)
				      ((< (cdr e1) (cdr e2)) #f)
				      (else
				       (string<=? (js-symbol->string! (car e1))
					  (js-symbol->string! (car e2))))))
			     (cddr what)))
		       (newline *profile-port*)))
	  *profile-caches*)
       (when (> total 0)
	  (fprint *profile-port*
	     "total accesses           : "
	     (padding total 12 'right))
	  (fprint *profile-port*
	     "dynamic accesses         : "
	     (padding js-profile-dynamic-accesses 12 'right)
	     " (" (percent js-profile-dynamic-accesses total) "%)")
	  (fprint *profile-port*
	     "total cache hits         : "
	     (padding (filecaches-hits filecaches) 12 'right)
	     " (" (percent (filecaches-hits filecaches) total) "%)")
	  (fprint *profile-port*
	     "total cache imap hits    : "
	     (padding (filecaches-imaps filecaches) 12 'right)
	     " (" (percent (filecaches-imaps filecaches) total) "%)")
	  (fprint *profile-port*
	     "total cache emap hits    : "
	     (padding (filecaches-emaps filecaches) 12 'right)
	     " (" (percent (filecaches-emaps filecaches) total) "%)")
	  (fprint *profile-port*
	     "total cache cmap hits    : "
	     (padding (filecaches-cmaps filecaches) 12 'right)
	     " (" (percent (filecaches-cmaps filecaches) total) "%)")
	  (fprint *profile-port*
	     "total cache pmap hits    : "
	     (padding (filecaches-pmaps filecaches) 12 'right)
	     " (" (percent (filecaches-pmaps filecaches) total) "%)")
	  (fprint *profile-port*
	     "total cache amap hits    : "
	     (padding (filecaches-amaps filecaches) 12 'right)
	     " (" (percent (filecaches-amaps filecaches) total) "%)")
	  (fprint *profile-port*
	     "total cache vtable hits  : "
	     (padding (filecaches-vtables filecaches) 12 'right)
	     " (" (percent (filecaches-vtables filecaches) total) "%)")
	  (fprint *profile-port*
	     "total cache misses       : "
	     (padding (filecaches-misses filecaches) 12 'right)
	     " (" (percent (filecaches-misses filecaches) total) "%)")
	  (fprint *profile-port*
	     "total uncaches           : "
	     (padding (total-uncaches) 12 'right)
	     " (" (percent (total-uncaches) total) "%)")
	  
	  (let ((l (sort (lambda (n1 n2) (<= (cdr n1) (cdr n2))) multi))
		(multi (apply + (map cdr multi))))
	     (fprint *profile-port*
		"total cache multiple     : "
		(padding multi 12 'right)
		" (" (percent multi total) "%) "
		(map car (take l (min (length l) 5)))))
	  (fprint *profile-port*
	     "hidden classes num       : "
	     (padding (gencmapid) 12 'right))
	  (fprint *profile-port*
	     "pmap invalidations       : "
	     (padding *pmap-invalidations* 12 'right))
	  (fprint *profile-port*
	     "vtables                  : "
	     (padding *vtables-cnt* 12 'right))
	  (fprint *profile-port*
	     "vtables size             : "
	     (padding (vector-mem-size *vtables-mem*) 12 'right) "b")
	  (multiple-value-bind (locations degree)
	     (max-vtable-entries)
	     (fprint *profile-port*
		"vtables locations        : "
		(padding locations 12 'right))
	     (fprint *profile-port*
		"vtables degree           : "
		(padding degree 12 'right))
	     (fprint *profile-port*
		"vtables conflicts        : "
		(padding *vtables-conflicts* 12 'right)))
	  (let ((srcs (delete-duplicates!
			 (map (lambda (pc)
				 (with-access::JsPropertyCache pc (src) src))
			    filecaches))))
	     (for-each (lambda (s)
			  (let ((pcs (filter (lambda (pc)
						(with-access::JsPropertyCache pc (src)
						   (string=? src s)))
					filecaches)))
			     (profile-pcache pcs)))
		srcs)))

       (if (string-contains trc "hopscript:uncache")
	   (let ((gets (sort (lambda (x y) (>= (cdr x) (cdr y)))
			  *profile-gets-props*))
		 (puts (sort (lambda (x y) (>= (cdr x) (cdr y)))
			  *profile-puts-props*))
		 (calls (sort (lambda (x y) (>= (cdr x) (cdr y)))
			   *profile-methods-props*)))
	      (newline *profile-port*) 
	      (fprint *profile-port*
		 "UNCACHED GETS:\n==============")
	      (profile-uncached gets *profile-gets*)
	      (newline *profile-port*)
	      (fprint *profile-port*
		 "UNCACHED PUTS:\n==============")
	      (profile-uncached puts *profile-puts*)
	      (newline *profile-port*)
	      (fprint *profile-port*
		 "UNCACHED METHODS:\n=================")
	      (profile-uncached calls *profile-methods*)
	      (newline *profile-port*))
	   (fprint *profile-port* "\n(use HOPTRACE=\"hopscript:uncache\" for uncached accesses)"))
       (cond-expand
	  (profile #f)
	  (else (fprint *profile-port* "reconfigure with --profile for loging xmap, amap, and pmap"))))))

;*---------------------------------------------------------------------*/
;*    profile-report-ctor ...                                          */
;*---------------------------------------------------------------------*/
(define (profile-report-ctor trc)
   
   (define filecaches
      (let ((m (pregexp-match "srcfile=([^ ]+)" trc)))
	 (if m
	     (let ((filename (cadr m)))
		(filter (lambda (info)
			   (string=? (js-function-info-path info) filename))
		   js-profile-ctors))
	     js-profile-ctors)))

   (define (display-ctor info)
      (display "      { \"point\": "       *profile-port*)
      (display (js-function-info-start info) *profile-port*)
      (display ", \"constrsize\": "  *profile-port*)
      (display (js-function-info-constrsize info) *profile-port*)
      (display "}" *profile-port*))

   (if (null? filecaches)
       (display "\"ctors\": []" *profile-port*)
       (begin
	  (display "\"ctors\": [\n" *profile-port*)
	  (display "  { \"filename\": \"" *profile-port*)
	  (display (js-function-info-path (car filecaches)) *profile-port*)
	  (display "\",\n"  *profile-port*)
	  (display "    \"ctors\": [\n" *profile-port*)
	  (display-ctor (car filecaches))
	  (for-each (lambda (info)
		       (display ",\n" *profile-port*)
		       (display-ctor info))
	     (cdr filecaches))
	  (display "]}\n]" *profile-port*))))

;*---------------------------------------------------------------------*/
;*    profile-uncached ...                                             */
;*---------------------------------------------------------------------*/
(define (profile-uncached entries total)
   (let loop ((es entries)
	      (sum 0))
      (when (and (pair? es) (> (/ (cdar es) total) 0.005))
	 (let ((e (car es)))
	    (fprint *profile-port* (padding (car e) 10 'right) ": "
	       (padding (cdr e) 10 'right)
	       (padding
		  (string-append " (" (number->string (percent (cdr e) total)) "%)")
		  7 'right)
	       (padding
		  (string-append " [" (number->string (percent (+ (cdr e) sum) total)) "%]")
		  7 'right))
	    (loop (cdr es) (+ sum (cdr e)))))))
		   
;*---------------------------------------------------------------------*/
;*    profile-pcache ...                                               */
;*---------------------------------------------------------------------*/
(define (profile-pcache pcaches)
   (when (any (lambda (pc)
		 (with-access::JsPropertyCache pc (point name
						     cntmiss
						     cntimap
						     cntemap
						     cntcmap
						     cntpmap
						     cntnmap
						     cntamap
						     cntxmap
						     cntvtable)
		    (> (+ cntmiss cntimap cntemap cntcmap cntpmap cntnmap cntamap cntxmap cntvtable)
		       *log-miss-threshold*)))
	    pcaches)
      (newline *profile-port*)
      (with-access::JsPropertyCache (car pcaches) (src)
	 (fprint *profile-port* src ": (" (length pcaches) ")")
	 (fprint *profile-port* (make-string (string-length src) #\=) "="))
      
      (let* ((pcache (sort (lambda (x y)
			      (with-access::JsPropertyCache x
				    ((p1 point))
				 (with-access::JsPropertyCache y
				       ((p2 point))
				    (< p1 p2))))
			pcaches))
	     (maxpoint (let ((pc (car (last-pair pcache))))
			  (with-access::JsPropertyCache pc (point)
			     (number->string point))))
	     (ppading (max (string-length maxpoint) 5))
	     (cwidth 8))
	 (fprint *profile-port* (padding "point" ppading 'center)
	    " "
	    (padding "property" cwidth 'center)
	    " "
	    (padding "use" 4 'center)
	    " | "
	    (padding "miss" cwidth 'right)
	    " " 
	    (padding "imap" cwidth 'right)
	    " "
	    (padding "emap" cwidth 'right)
	    " "
	    (padding "cmap" cwidth 'right)
	    " "
	    (padding "pmap" cwidth 'right)
	    " " 
	    (padding "nmap" cwidth 'right)
	    " " 
	    (padding "amap" cwidth 'right)
	    " " 
	    (padding "xmap" cwidth 'right)
	    " " 
	    (padding "vtable" cwidth 'right))
	 (fprint *profile-port* (make-string (+ ppading 1 cwidth 1 4) #\-)
	    "-+-"
	    (make-string (* 9 (+ cwidth 1)) #\-))
	 (for-each (lambda (pc)
		      (with-access::JsPropertyCache pc (point name usage
							  cntmiss
							  cntimap
							  cntemap
							  cntcmap
							  cntpmap
							  cntnmap
							  cntamap
							  cntxmap
							  cntvtable)
			 (when (> (+ cntmiss cntimap cntemap cntcmap cntpmap cntnmap cntamap cntxmap cntvtable)
				  *log-miss-threshold*)
			    (fprint *profile-port*
			       (padding (number->string point) ppading 'right)
			       " " 
			       (padding name cwidth 'right)
			       " " 
			       (padding usage 4)
			       " | "
			       (padding cntmiss cwidth 'right)
			       " " 
			       (padding cntimap cwidth 'right)
			       " " 
			       (padding cntemap cwidth 'right)
			       " " 
			       (padding cntcmap cwidth 'right)
			       " " 
			       (padding cntpmap cwidth 'right)
			       " " 
			       (padding cntnmap cwidth 'right)
			       " " 
			       (padding cntamap cwidth 'right)
			       " " 
			       (padding cntxmap cwidth 'right)
			       " " 
			       (padding cntvtable cwidth 'right)))))
	    pcaches))))

;*---------------------------------------------------------------------*/
;*    profile-calls ...                                                */
;*---------------------------------------------------------------------*/
(define (profile-calls trc symtable)

   (define (find-def sym symtable)
      (let ((entry (find (lambda (entry)
			    (and (eq? (cadr entry) 'fun)
				 (eq? (caddr entry) sym)))
		      symtable)))
	 (when entry (car entry))))

   (define (find-def-by-loc loc symtable)
      (let ((entry (find (lambda (entry)
			    (and (eq? (cadr entry) 'fun)
				 (eq? (car entry) loc)))
		      symtable)))
	 (unless entry (tprint "CANNOT FIND fun loc=" loc))
	 (when entry (car entry))))
   
   (define (get-target loc symtable)
      (let ((c (assq loc symtable)))
	 (if (pair? c) (find-def-by-loc (cadddr c) symtable) -1)))
   
   (define (print-call-counts-json counts locations)
      (let ((sep "\n      "))
	 (for-each (lambda (nl)
		      (let ((n (car nl))
			    (l (cdr nl)))
			 (when (and (>=fx l 0) (or (not (number? n)) (> n 0)))
			    (display sep)
			    (set! sep ",\n      ")
			    (if (number? n)
				;; direct call
				(printf "{ \"point\": ~a, \"cnt\": ~a }" l n) 
				;; unknown call
				(printf "{ \"point\": ~a, \"cnt\": [ ~(, ) ] }" l
				   (map (lambda (n)
					   (format "{ \"point\": ~a, \"cnt\": ~a }"
					      (car n) (cdr n)))
				      n))))))
	    (sort (lambda (x y)
		     (< (cdr x) (cdr y)))
	       (map cons counts locations)))))

   (define (print-call-counts-memviz counts locations)
      (let ((sep "\n      "))
	 (for-each (lambda (nl)
		      (let ((n (car nl))
			    (l (cdr nl)))
			 (when (and (>=fx l 0) (or (not (number? n)) (> n 0)))
			    (display sep)
			    (set! sep ",\n      ")
			    (if (number? n)
				;; direct call
				(printf "{ \"point\": ~a, \"cnt\": ~a, \"target\": ~a }" l n
				   (get-target l symtable))
				;; unknown call
				(printf "{ \"point\": ~a, \"cnt\": [ ~(, ) ] }" l
				   (map (lambda (n)
					   (format "{ \"target\": ~a, \"cnt\": ~a }"
					      (car n) (cdr n)))
				      n))))))
	    (sort (lambda (x y)
		     (< (cdr x) (cdr y)))
	       (map cons counts locations)))))

   (define (print-call-counts counts locations)
      (for-each (lambda (nl)
		   (let ((n (car nl))
			 (l (cdr nl)))
		      (when (and (>=fx l 0) (or (not (number? n)) (> n 0)))
			 (if (number? n)
			     ;; direct call
			     (printf "   ~a: ~a\n" l n) 
			     ;; unknown call
			     (printf "   ~a: ~(, )\n" l
				(map (lambda (n)
					(format "~a@~a" (cdr n) (car n)))
				   n))))))
	 (sort (lambda (x y)
		  (< (cdr x) (cdr y)))
	    (map cons counts locations))))
   
   (cond
      ((or (string-contains trc "format:pgo")
	   (string-contains trc "format:json"))
       (with-output-to-port *profile-port*
	  (lambda ()
	     (print "\"calls\": [")
	     (let ((first #f))
		(for-each (lambda (t)
			     (when first
				(set! first #f)
				(print ","))
			     (print "  { \"filename\": \""
				(vector-ref t 0) "\",")
			     (display "    \"calls\": [")
			     (print-call-counts-json
				(vector->list (vector-ref t 1))
				(vector->list (vector-ref t 3)))
			     (print " ] }"))
		   *profile-call-tables*))
	     (print "],"))))
      ((string-contains trc "format:memviz")
       (with-output-to-port *profile-port*
	  (lambda ()
	     (print "\"calls\": [")
	     (let ((first #f))
		(for-each (lambda (t)
			     (when first
				(set! first #f)
				(print ","))
			     (print "  { \"filename\": \""
				(vector-ref t 0) "\",")
			     (display "    \"calls\": [")
			     (print-call-counts-memviz
				(vector->list (vector-ref t 1))
				(vector->list (vector-ref t 3)))
			     (print " ] }"))
		   *profile-call-tables*))
	     (print "],"))))
      (else
       (with-output-to-port *profile-port*
	  (lambda ()
	     (let ((first #f))
		(for-each (lambda (t)
			     (print "filename: " (vector-ref t 0))
			     (print-call-counts
				(vector->list (vector-ref t 1))
				(vector->list (vector-ref t 3))))
		   *profile-call-tables*)))))))

;*---------------------------------------------------------------------*/
;*    profile-cmaps ...                                                */
;*---------------------------------------------------------------------*/
(define (profile-cmaps trc)

   (define (print-call-counts counts locations)
      (let ((sep "\n      "))
	 (for-each (lambda (nl)
		      (let ((n (car nl))
			    (l (cdr nl)))
			 (when (and (>=fx l 0) (pair? n))
			    (display sep)
			    (set! sep ",\n      ")
			    (printf "{ \"point\": ~a, \"cnt\": [ ~(, ) ] }" l
			       (map cdr n)))))
	    (sort (lambda (x y)
		     (< (cdr x) (cdr y)))
	       (map cons counts locations)))))

   (when (string-contains trc "format:pgo")
      (with-output-to-port *profile-port*
	 (lambda ()
	    (print "\"cmaps\": [")
	    (let ((first #f))
	       (for-each (lambda (t)
			    (when first
			       (set! first #f)
			       (print ","))
			    (print "  { \"filename\": \""
			       (vector-ref t 0) "\",")
			    (display "    \"cmaps\": [")
			    (print-call-counts
			       (vector->list (vector-ref t 2))
			       (vector->list (vector-ref t 3)))
			    (print " ] }"))
		  *profile-call-tables*))
	    (print "],")))))

;*---------------------------------------------------------------------*/
;*    profile-symtable ...                                             */
;*---------------------------------------------------------------------*/
(define (profile-symtable trc symtable conf)
   (cond
      ((string-contains trc "format:memviz")
       (with-output-to-port *profile-port*
	  (lambda ()
	     (display "\"symbols\": ")
	     (json-array 2 (lambda (entry)
			      (printf "  { \"point\": ~a, \"type\": \"~a\", \"name\": \"~a\", \"endpoint\": ~a }"
				 (car entry) (cadr entry) (caddr entry) (cadddr entry)))
		(filter (lambda (entry) (eq? (cadr entry) 'fun)) symtable))
	     (print ","))))
      (else
       (with-output-to-port *profile-port*
	  (lambda ()
	     (print "symbols:")
	     (for-each (lambda (entry)
			  (print "  " (car entry) ": " (caddr entry)
			     " (" (cadr entry) ")"))
		symtable))))))

;*---------------------------------------------------------------------*/
;*    json-array ...                                                   */
;*---------------------------------------------------------------------*/
(define (json-array margin proc lst::pair-nil)
   (cond
      ((null? lst)
       (display "[]"))
      ((null? (cdr lst))
       (display "[")
       (proc (car lst))
       (display "]"))
      (else
       (print "[")
       (let loop ((lst (cdr lst)))
	  (proc (car lst))
	  (if (null? (cdr lst))
	      (display "\n]")
	      (begin
		 (print ",")
		 (loop (cdr lst))))))))

