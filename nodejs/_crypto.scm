;*=====================================================================*/
;*    serrano/prgm/project/hop/3.5.x/nodejs/_crypto.scm                */
;*    -------------------------------------------------------------    */
;*    Author      :  Manuel Serrano                                    */
;*    Creation    :  Sat Aug 23 08:47:08 2014                          */
;*    Last change :  Sun Jan 23 08:36:45 2022 (serrano)                */
;*    Copyright   :  2014-22 Manuel Serrano                            */
;*    -------------------------------------------------------------    */
;*    Crypto native bindings                                           */
;*=====================================================================*/

;*---------------------------------------------------------------------*/
;*    The module                                                       */
;*---------------------------------------------------------------------*/
(module __nodejs__crypto

   (cond-expand
      (enable-ssl (library ssl)))

   (include "nodejs_debug.sch" "_crypto.sch")
   (include "../hopscript/stringthread.sch")
   
   (library hopscript)

   (cond-expand
      (enable-ssl
       (static  (class JsSecureContext::JsObject
		   (ctx (default #unspecified)))
	  
	  (class JsSSLConnection::JsObject
	     (hparser::HelloParser read-only)
	     (ssl (default #unspecified))
	     (next-session::pair-nil (default '())))
	  
	  (class JsDH::JsObject
	     (dh (default #unspecified))
	     (initp::bool (default #f)))
	  
	  (class JsHash::JsObject
	     (hash::ssl-hash read-only))
	  
	  (class JsHmac::JsObject
	     (hmac::obj (default #unspecified)))
	  
	  (class JsSign::JsObject
	     (sign::ssl-sign read-only))
	  
	  (class JsVerify::JsObject
	     (verify::ssl-verify read-only))
	  
	  (class JsCipher::JsObject
	     (cipher::ssl-cipher read-only))
	  
	  (class JsDecipher::JsCipher)
	  
	  (class HelloParser
	     (%worker::WorkerHopThread read-only)
	     (%this::JsGlobalObject read-only)
	     (state::symbol (default 'kWaiting))
	     (data::bstring (default (make-string 18432)))
	     (offset::long (default 0))
	     (body-offset::long (default 0))
	     (frame-len::long (default 0))
	     (conn::JsSSLConnection (default (class-nil JsSSLConnection)))))))
	       
   (import  __nodejs_process
	    __nodejs__buffer
	    __nodejs_uv)
   
   (export  (crypto-constants::pair-nil)
	    (process-crypto ::WorkerHopThread ::JsGlobalObject)))

;*---------------------------------------------------------------------*/
;*    &begin!                                                          */
;*---------------------------------------------------------------------*/
(define __js_strings (&begin!))

;*---------------------------------------------------------------------*/
;*    js-toprimitive ...                                               */
;*---------------------------------------------------------------------*/
(cond-expand
   (enable-ssl
(define-method (js-toprimitive obj::JsSSLConnection preferredtype %this::JsGlobalObject)
   (& "[object SSLConnection]"))
))

;*---------------------------------------------------------------------*/
;*    ignored-verify-errors ...                                        */
;*    -------------------------------------------------------------    */
;*    As of 30 septembre 2021, Let's encrypt DST ROOT CA X3            */
;*    certificate has expired, which has caused many web sites to      */
;*    collapse. Apparently, the "old" Nodejs version Hop still         */
;*    relies on is not able to correctly handle the work around        */
;*    the crypto crowd has invented. Checking the newer Nodejs         */
;*    version I have the vague impression that removing the            */
;*    expired validy check should be enough. That's what I did         */
;*    here. I have no idea wether this is correct or not but           */
;*    apparently it solves the problem Hop had to connect with         */
;*    SSL servers that were using the incriminated certificate.        */
;*                                                                     */
;*    Extra information can be found here:                             */
;*                                                                     */
;*    https://letsencrypt.org/docs/dst-root-ca-x3-expiration-          */
;*      september-2021/                                                */
;*    https://letsencrypt.org/certificates/                            */
;*    https://scotthelme.co.uk/lets-encrypt-old-root-expiration/       */
;*---------------------------------------------------------------------*/
(define ignored-verify-errors
   '("CERT_HAS_EXPIRED"))

;*---------------------------------------------------------------------*/
;*    constructors                                                     */
;*---------------------------------------------------------------------*/
(define-instantiate JsSecureContext)
(define-instantiate JsSSLConnection)
(define-instantiate JsDH)
(define-instantiate JsHash)
(define-instantiate JsHmac)
(define-instantiate JsSign)
(define-instantiate JsVerify)
(define-instantiate JsCipher)
(define-instantiate JsDecipher)

;*---------------------------------------------------------------------*/
;*    debug-crypto ...                                                 */
;*---------------------------------------------------------------------*/
(define debug-crypto
   (let ((env (getenv "NODE_DEBUG")))
      (cond
	 ((not (string? env)) 0)
	 ((string-contains env "_crypto") 2)
	 (else 0))))

(cond-expand
   (enable-ssl

;*---------------------------------------------------------------------*/
;*    crypto-constants ...                                             */
;*---------------------------------------------------------------------*/
(define (crypto-constants)
   `((SSL_OP_CIPHER_SERVER_PREFERENCE . ,(ssl-op-cipher-server-preference))))

;*---------------------------------------------------------------------*/
;*    process-crypto ...                                               */
;*---------------------------------------------------------------------*/
(define (process-crypto %worker %this)
   
   (define __init (set! __js_strings (&init!)))
   
   (define (secure-context-init this . args)
      (with-access::JsSecureContext this (ctx)
	 (let ((met (if (pair? args)
			(js-tostring (car args) %this)
			"default")))
	    (set! ctx (instantiate::secure-context (method met))))))
   
   (define (secure-context-close this)
      (with-access::JsSecureContext this (ctx)
	 (secure-context-close ctx)))
   
   (define (add-root-certs this)
      (with-access::JsSecureContext this (ctx)
	 (secure-context-add-root-certs! ctx)))
   
   (define (add-ca-cert this cert)
      (with-access::JsSecureContext this (ctx)
	 (if (js-jsstring? cert)
	     (let ((cert (js-jsstring->string cert)))
		(secure-context-add-ca-cert! ctx cert 0 (string-length cert)))
	     (with-access::JsTypedArray cert (%data byteoffset length)
		(secure-context-add-ca-cert! ctx %data
		   (uint32->fixnum byteoffset)
		   (js-get cert (& "length") %this))))))
   
   (define (add-crl this cert)
      (with-access::JsSecureContext this (ctx)
	 (if (js-jsstring? cert)
	     (let ((cert (js-jsstring->string cert)))
		(secure-context-add-crl! ctx cert 0 (string-length cert)))
	     (with-access::JsTypedArray cert (%data byteoffset length)
		(secure-context-add-crl! ctx %data
		   (uint32->fixnum byteoffset)
		   (js-get cert (& "length") %this))))))
   
   (define (set-key this cert passphrase)
      (with-access::JsSecureContext this (ctx)
	 (let ((pass (when (js-jsstring? passphrase)
			(js-jsstring->string passphrase))))
	    (if (js-jsstring? cert)
		(let ((cert (js-jsstring->string cert)))
		   (secure-context-set-key! ctx cert 0 (string-length cert) pass))
		(with-access::JsTypedArray cert (%data byteoffset length)
		   (secure-context-set-key! ctx %data
		      (uint32->fixnum byteoffset)
		      (js-get cert (& "length") %this)
		      pass))))))
   
   (define (set-cert this cert)
      (with-access::JsSecureContext this (ctx)
	 (if (js-jsstring? cert)
	     (let ((cert (js-jsstring->string cert)))
		(secure-context-set-cert! ctx cert 0 (string-length cert)))
	     (with-access::JsTypedArray cert (%data byteoffset length)
		(secure-context-set-cert! ctx %data
		   (uint32->fixnum byteoffset)
		   (uint32->fixnum length))))))
   
   (define (set-session-id-context this sic)
      (with-access::JsSecureContext this (ctx)
	 (if (js-jsstring? sic)
	     (let ((sic (js-jsstring->string sic)))
		(secure-context-set-session-id-context! ctx sic 0 (string-length sic)))
	     (with-access::JsTypedArray sic (%data byteoffset length)
		(secure-context-set-session-id-context! ctx %data
		   (uint32->fixnum byteoffset)
		   (uint32->fixnum length))))))
   
   (define (load-pkcs12 this pfx pass)
      (let ((pass (cond
		     ((js-jsstring? pass)
		      (js-jsstring->string pass))
		     ((isa? pass JsTypedArray)
		      (with-access::JsTypedArray pass (%data byteoffset length)
			 (substring %data
			    (uint32->fixnum byteoffset)
			    (+fx (uint32->fixnum byteoffset)
			       (uint32->fixnum length)))))
		     (else
		      #f))))
	 (with-access::JsSecureContext this (ctx)
	    (cond
	       ((js-jsstring? pfx)
		(secure-context-load-pkcs12 ctx
		   (js-jsstring->string pfx) pass))
	       ((isa? pfx JsTypedArray)
		(with-access::JsTypedArray pfx (%data byteoffset length)
		   (secure-context-load-pkcs12 ctx
		      (substring %data
			 (uint32->fixnum byteoffset)
			 (+fx (uint32->fixnum byteoffset)
			    (uint32->fixnum length)))
		      pass)))
	       (else
		(js-raise-type-error %this
		   (format "Bad parameter (~a, ~a) ~~a" (typeof pfx) (typeof pass))
		   pfx))))))
   
   (define (set-ciphers this ciphers)
      (with-access::JsSecureContext this (ctx)
	 (cond
	    ((js-jsstring? ciphers)
	     (secure-context-set-ciphers! ctx (js-jsstring->string ciphers)))
	    (else
	     (js-raise-type-error %this
		(format "Bad parameter (~a) ~~a" (typeof ciphers))
		ciphers)))))
   
   (define (set-options this options)
      (with-access::JsSecureContext this (ctx)
	 (if (integer? options)
	     (secure-context-set-options! ctx options)
	     (js-raise-type-error %this "Bad parameter ~a" options))))
   
   (define secure-context-proto
      (let ((proto (with-access::JsGlobalObject %this (js-object)
		      (js-new %this js-object))))
	 (js-put! proto (& "init")
	    (js-make-function %this secure-context-init
	       (js-function-arity secure-context-init)
	       (js-function-info :name "init" :len 1))
	    #f %this)
	 (js-put! proto (& "close")
	    (js-make-function %this secure-context-close
	       (js-function-arity secure-context-close)
	       (js-function-info :name "close" :len 0))
	    #f %this)
	 (js-put! proto (& "addRootCerts")
	    (js-make-function %this add-root-certs
	       (js-function-arity add-root-certs)
	       (js-function-info :name "addRootCerts" :len 0))
	    #f %this)
	 (js-put! proto (& "addCACert")
	    (js-make-function %this add-ca-cert
	       (js-function-arity add-ca-cert)
	       (js-function-info :name "addCACert" :len 1))
	    #f %this)
	 (js-put! proto (& "addCRL")
	    (js-make-function %this add-crl
	       (js-function-arity add-crl)
	       (js-function-info :name "addCRL" :len 1))
	    #f %this)
	 (js-put! proto (& "setKey")
	    (js-make-function %this set-key
	       (js-function-arity set-key)
	       (js-function-info :name "setKey" :len 2))
	    #f %this)
	 (js-put! proto (& "setCert")
	    (js-make-function %this set-cert
	       (js-function-arity set-cert)
	       (js-function-info :name "setCert" :len 1))
	    #f %this)
	 (js-put! proto (& "setSessionIdContext")
	    (js-make-function %this set-session-id-context
	       (js-function-arity set-session-id-context)
	       (js-function-info :name "setSessionIdContext" :len 2))
	    #f %this)
	 (js-put! proto (& "loadPKCS12")
	    (js-make-function %this load-pkcs12
	       (js-function-arity load-pkcs12)
	       (js-function-info :name "loadPKCS12" :len 2))
	    #f %this)
	 (js-put! proto (& "setCiphers")
	    (js-make-function %this set-ciphers
	       (js-function-arity set-ciphers)
	       (js-function-info :name "setCiphers" :len 2))
	    #f %this)
	 (js-put! proto (& "setOptions")
	    (js-make-function %this set-options
	       (js-function-arity set-options)
	       (js-function-info :name "setOptions" :len 2))
	    #f %this)
	 
	 proto))
   
   (define c -1)
   (define (count)
      (set! c (+fx c 1))
      c)
   
   (define (connection-start this)
      (with-access::JsSSLConnection this (ssl)
	 (ssl-connection-start ssl)))
   
   (define (connection-close this)
      (with-access::JsSSLConnection this (ssl)
	 (ssl-connection-close ssl)))
   
   (define (connection-shutdown this)
      (with-access::JsSSLConnection this (ssl)
	 (ssl-connection-shutdown ssl)))
   
   (define (connection-encout this buffer offset len)
      (with-access::JsTypedArray buffer (length)
	 (when (>fx debug-crypto 0)
	    (tprint ">>> EncOut(" (count) ") buffer=" length
	       " offset=" offset
	       " len=" len)))
      (with-access::JsSSLConnection this (ssl)
	 (with-access::JsTypedArray buffer (%data byteoffset length)
	    (when (>fx debug-crypto 0)
	       (tprint "~~~ EncOut(" (count) ") offset="
		  (+fx (uint32->fixnum byteoffset) offset)
		  " len=" len))
	    (let ((r (ssl-connection-read ssl %data
			(+fx (uint32->fixnum byteoffset) offset) len)))
	       (when (>fx debug-crypto 0)
		  (tprint "<<< EncOut(" (count) ") => " r))
	       r))))
   
   (define (connection-write this::JsSSLConnection buffer len)
      (error "connection-write" "Not implemented" (typeof buffer)))
   
   (define (connection-encin this::JsSSLConnection buffer offset len)
      (with-access::JsTypedArray buffer (length)
	 (when (>fx debug-crypto 0)
	    (tprint "EncIn(" (count) ") buffer=" length
	       " offset=" offset
	       " len=" len)))
      (with-access::JsSSLConnection this (ssl hparser)
	 (with-access::ssl-connection ssl (isserver)
	    (with-access::JsTypedArray buffer (%data byteoffset length)
;* 	       (when (>fx debug-crypto 0)                              */
;* 		  (tprint "EncInc byteoffset=" byteoffset))            */
	       (if (and isserver (not (hello-parser-ended hparser)))
		   (let ((r (hello-parser-write hparser %data
			       (+fx (uint32->fixnum byteoffset) offset) len)))
		      (when (>fx debug-crypto 0)
			 (tprint "HelloParser bytes_written=" r))
		      r)
		   (begin
		      (when (>fx debug-crypto 0)
			 (tprint "BIO_write.2 len=" len))
		      (let ((r (ssl-connection-write ssl %data
				  (+fx (uint32->fixnum byteoffset) offset) len)))
			 (when (>fx debug-crypto 0)
			    (let ((len (if (<fx len 160) len 160))
				  (p (open-output-string))
				  (off (+fx (uint32->fixnum byteoffset) offset)))
			       (let loop ((i 0))
				  (if (=fx i len)
				      (tprint "EncIn data=" (close-output-port p))
				      (begin
					 (display (format "~2,0x "
						     (char->integer
							(string-ref %data (+fx off i))))
					    p)
					 (loop (+fx i 1))))))
			    (tprint "ClientWritten bytes_written=" r))
			 r)))))))
   
   (define (connection-clearin this::JsSSLConnection buffer offset len)
      (with-access::JsTypedArray buffer (length byteoffset)
	 (when (>fx debug-crypto 0)
	    (tprint "ClearIn(" (count) ") buffer=" length
	       " offset=" offset " byteoffset=" byteoffset
	       " len=" len)))
      (with-access::JsSSLConnection this (ssl)
	 (with-access::JsTypedArray buffer (%data byteoffset length)
	    (ssl-connection-clear-in ssl %data
	       (+fx (uint32->fixnum byteoffset) offset) len))))
   
   (define (connection-clearout this buffer offset len)
      (with-access::JsTypedArray buffer (length)
	 (when (>fx debug-crypto 0)
	    (tprint ">>> ClearOut(" (count) ") buffer=" length
	       " offset=" offset
	       " len=" len)))
      (with-access::JsSSLConnection this (ssl)
	 (with-access::JsTypedArray buffer (%data byteoffset length)
	    (let ((r (ssl-connection-clear-out ssl %data
			(+fx (uint32->fixnum byteoffset) offset) len)))
	       (when (>fx debug-crypto 0)
		  (tprint "<<< ClearOut(" (count) ") res=" r))
	       r))))
   
   (define (connection-is-init-finished this)
      (with-access::JsSSLConnection this (ssl)
	 (ssl-connection-init-finished? ssl)))
   
   (define (connection-enc-pending this)
      (with-access::JsSSLConnection this (ssl)
	 (ssl-connection-enc-pending ssl)))
   
   (define (connection-clear-pending this)
      (with-access::JsSSLConnection this (ssl)
	 (ssl-connection-clear-pending ssl)))
   
   (define (connection-set-session this buffer)
      (with-access::JsSSLConnection this (ssl)
	 (with-access::JsTypedArray buffer (%data byteoffset length)
	    (ssl-connection-set-session ssl %data))))
   
   (define (connection-get-session this)
      (with-access::JsSSLConnection this (ssl)
	 (let ((sess (ssl-connection-get-session ssl)))
	    (if (string? sess)
		(js-string->jsfastbuffer sess %this)
		(js-raise-type-error %this "Bad session" sess)))))
   
   (define (connection-get-current-cipher this)
      (with-access::JsSSLConnection this (ssl)
	 (let ((c (ssl-connection-get-current-cipher ssl)))
	    (if (pair? c)
		(with-access::JsGlobalObject %this (js-object)
		   (let ((o (js-new %this js-object)))
		      (js-put! o (& "name") (js-string->jsstring (car c)) #f %this)
		      (js-put! o (& "version") (js-string->jsstring (cdr c)) #f %this)
		      o))
		(js-undefined)))))
   
   (define (connection-load-session this::JsSSLConnection buffer)
      (when (>fx debug-crypto 0)
	 (tprint "LoadSession"))
      (with-access::JsSSLConnection this (ssl hparser)
	 (when (isa? buffer JsTypedArray)
	    (when (>fx debug-crypto 0)
	       (tprint "LoadSession, with buffer"))
	    (with-access::JsTypedArray buffer (%data byteoffset length)
	       (ssl-connection-load-session ssl %data)))
	 (hello-parser-finish hparser)
	 #t))
   
   (define (connection-verify-error this)
      (with-access::JsSSLConnection this (ssl)
	 (let ((err (ssl-connection-verify-error ssl)))
	    (if (and (string? err) (not (member err ignored-verify-errors)))
		(with-access::JsGlobalObject %this (js-error)
		   (js-new %this js-error (js-string->jsstring err)))
		(js-null)))))
   
   (define (connection-get-peer-certificate this)
      (with-access::JsSSLConnection this (ssl)
	 (let ((cert (ssl-connection-get-peer-certificate ssl)))
	    (if (pair? cert)
		(let ((eku (assq 'ext-key-usage cert)))
		   (when (pair? eku)
		      (vector-map! js-string->jsstring (cdr eku))
		      (set-car! eku 'ext_key_usage)
		      (set-cdr! eku (js-vector->jsarray (cdr eku) %this)))
		   (js-alist->jsobject cert %this))
		(js-undefined)))))
   
   (define (connection-session-reused? this)
      (with-access::JsSSLConnection this (ssl)
	 (ssl-connection-reused? ssl)))
   
   (define (connection-get-negotiated-protocol this)
      (with-access::JsSSLConnection this (ssl)
	 (let ((s (ssl-connection-get-negotiated-protocol ssl)))
	    (if (string? s)
		(js-string->jsstring s)
		s))))
   
   (define (connection-set-npn-protocols this protos)
      (with-access::JsSSLConnection this (ssl)
	 (with-access::ssl-connection ssl (npn-protos)
	    (with-access::JsTypedArray protos (%data byteoffset length)
	       (set! npn-protos
		  (substring %data
		     (uint32->fixnum byteoffset)
		     (uint32->fixnum (+u32 byteoffset length))))))))
   
   (define (connection-get-servername this)
      (with-access::JsSSLConnection this (ssl)
	 (with-access::ssl-connection ssl (server-name)
	    (if (string? server-name)
		(js-string->jsstring server-name)
		server-name))))
   
   (define (connection-set-sni-callback this cb)
      (with-access::JsSSLConnection this (ssl)
	 (with-access::ssl-connection ssl (sni-context-callback)
	    (set! sni-context-callback
	       (lambda (ssl srvname)
		  (let ((r (!js-callback1 "set-sni" %worker %this cb
			      this (js-string->jsstring srvname))))
		     (when (isa? r JsSecureContext)
			(with-access::JsSecureContext r (ctx)
			   ctx))))))))
   
   (define connection-proto
      (let ((proto (with-access::JsGlobalObject %this (js-object)
		      (js-new %this js-object))))
	 (js-put! proto (& "start")
	    (js-make-function %this connection-start
	       (js-function-arity connection-start)
	       (js-function-info :name "start" :len 0))
	    #f %this)
	 (js-put! proto (& "close")
	    (js-make-function %this connection-close
	       (js-function-arity connection-close)
	       (js-function-info :name "close" :len 0))
	    #f %this)
	 (js-put! proto (& "shutdown")
	    (js-make-function %this connection-shutdown
	       (js-function-arity connection-shutdown)
	       (js-function-info :name "shutdown" :len 0))
	    #f %this)
	 (js-put! proto (& "encOut")
	    (js-make-function %this connection-encout
	       (js-function-arity connection-encout)
	       (js-function-info :name "encOut" :len 3))
	    #f %this)
	 (js-put! proto (& "encIn")
	    (js-make-function %this connection-encin
	       (js-function-arity connection-encin)
	       (js-function-info :name "encIn" :len 3))
	    #f %this)
	 (js-put! proto (& "clearIn")
	    (js-make-function %this connection-clearin
	       (js-function-arity connection-clearin)
	       (js-function-info :name "clearIn" :len 3))
	    #f %this)
	 (js-put! proto (& "clearOut")
	    (js-make-function %this connection-clearout
	       (js-function-arity connection-clearout)
	       (js-function-info :name "clearOut" :len 3))
	    #f %this)
	 (js-put! proto (& "isInitFinished")
	    (js-make-function %this connection-is-init-finished
	       (js-function-arity connection-is-init-finished)
	       (js-function-info :name "isInitFinished" :len 0))
	    #f %this)
	 (js-put! proto (& "encPending")
	    (js-make-function %this connection-enc-pending
	       (js-function-arity connection-enc-pending)
	       (js-function-info :name "encPending" :len 0))
	    #f %this)
	 (js-put! proto (& "clearPending")
	    (js-make-function %this connection-clear-pending
	       (js-function-arity connection-clear-pending)
	       (js-function-info :name "clearPending" :len 0))
	    #f %this)
	 (js-put! proto (& "setSession")
	    (js-make-function %this connection-set-session
	       (js-function-arity connection-set-session)
	       (js-function-info :name "setSession" :len 1))
	    #f %this)
	 (js-put! proto (& "getSession")
	    (js-make-function %this connection-get-session
	       (js-function-arity connection-get-session)
	       (js-function-info :name "getSession" :len 0))
	    #f %this)
	 (js-put! proto (& "getCurrentCipher")
	    (js-make-function %this connection-get-current-cipher
	       (js-function-arity connection-get-current-cipher)
	       (js-function-info :name "getCurrentCipher" :len 0))
	    #f %this)
	 (js-put! proto (& "loadSession")
	    (js-make-function %this connection-load-session
	       (js-function-arity connection-load-session)
	       (js-function-info :name "loadSession" :len 1))
	    #f %this)
	 (js-put! proto (& "verifyError")
	    (js-make-function %this connection-verify-error
	       (js-function-arity connection-verify-error)
	       (js-function-info :name "verifyError" :len 1))
	    #f %this)
	 (js-put! proto (& "getPeerCertificate")
	    (js-make-function %this connection-get-peer-certificate
	       (js-function-arity connection-get-peer-certificate)
	       (js-function-info :name "getPeerCertificate" :len 1))
	    #f %this)
	 (js-put! proto (& "isSessionReused")
	    (js-make-function %this connection-session-reused?
	       (js-function-arity connection-session-reused?)
	       (js-function-info :name "isSessionReused" :len 1))
	    #f %this)
	 (js-put! proto (& "getNegotiatedProtocol")
	    (js-make-function %this connection-get-negotiated-protocol
	       (js-function-arity connection-get-negotiated-protocol)
	       (js-function-info :name "getNegotiatedProtocol" :len 0))
	    #f %this)
	 (js-put! proto (& "setNPNProtocols")
	    (js-make-function %this connection-set-npn-protocols
	       (js-function-arity connection-set-npn-protocols)
	       (js-function-info :name "setNPNProtocols" :len 1))
	    #f %this)
	 (js-put! proto (& "getServername")
	    (js-make-function %this connection-get-servername
	       (js-function-arity connection-get-servername)
	       (js-function-info :name "getServername" :len 0))
	    #f %this)
	 (js-put! proto (& "setSNICallback")
	    (js-make-function %this connection-set-sni-callback
	       (js-function-arity connection-set-sni-callback)
	       (js-function-info :name "setSNICallback" :len 1))
	    #f %this)
	 proto))
   
   (define (secure-context this . args)
      (instantiateJsSecureContext
	 (__proto__ secure-context-proto)))
   
   (define (info-callback this state)
      (when (>fx debug-crypto 0)
	 (tprint ">>> info-callback state=" state))
      (if (=fx state 0)
	  ;; start
	  (let ((onhandshakestart (js-get this (& "onhandshakestart") %this)))
	     (when (>fx debug-crypto 0)
		(tprint "onhandshakestart"))
	     (!js-callback0 "onhandshakestart" %worker %this
		onhandshakestart this))
	  ;; done
	  (let ((onhandshakedone (js-get this (& "onhandshakedone") %this)))
	     (when (>fx debug-crypto 0)
		(tprint "onhandshakedone"))
	     (!js-callback0 "onhandshakedone" %worker %this
		onhandshakedone this)))
      (when (>fx debug-crypto 0)
	 (tprint "<<< info-callback")))
   
   (define (newsession-callback this session-id::bstring serialized::bstring)
      (let ((onnewsession (js-get this (& "onnewsession") %this)))
	 (!js-callback2 "onnewsession" %worker %this
	    onnewsession this
	    (js-string->jsfastbuffer session-id %this)
	    (js-string->jsfastbuffer serialized %this))))
   
   (define (connection this jsctx serverp request-cert-or-server-name reject)
      (with-access::JsSecureContext jsctx (ctx)
	 (letrec* ((hparser (instantiate::HelloParser
			       (%worker %worker)
			       (%this %this)))
		   (conn (instantiateJsSSLConnection
			    (__proto__ connection-proto)
			    (hparser hparser)
			    (ssl (instantiate::ssl-connection
				    (ctx ctx)
				    (info-callback (lambda (start-or-done)
						      (info-callback
							 conn start-or-done)))
				    (newsession-callback (lambda (session-id serialized)
							    (newsession-callback conn
							       session-id serialized)))
				    (isserver (js-toboolean serverp))
				    (request-cert (when serverp
						     request-cert-or-server-name))
				    (server-name (unless serverp
						    (when (js-jsstring? request-cert-or-server-name)
						       (js-jsstring->string request-cert-or-server-name))))
				    (reject-unauthorized reject))))))
	    (with-access::HelloParser hparser ((hconn conn))
	       (set! hconn conn))
	    (js-bind! %this conn (& "receivedShutdown")
	       :get (js-make-function %this
		       (lambda (this)
			  (with-access::JsSSLConnection this (ssl)
			     (with-access::ssl-connection ssl (received-shutdown)
				(or received-shutdown (js-undefined)))))
		       (js-function-arity 0 0)
		       (js-function-info :name "receivedShutdown" :len 0)))
	    (js-bind! %this conn (& "sentShutdown")
	       :get (js-make-function %this
		       (lambda (this)
			  (with-access::JsSSLConnection this (ssl)
			     (with-access::ssl-connection ssl (sent-shutdown)
				(or sent-shutdown (js-undefined)))))
		       (js-function-arity 0 0)
		       (js-function-info :name "sentShutdown" :len 0)))
	    (js-bind! %this conn (& "error")
	       :get (js-make-function %this
		       (lambda (this)
			  (with-access::JsSSLConnection this (ssl)
			     (with-access::ssl-connection ssl (err)
				(if (string? err)
				    (with-access::JsGlobalObject %this (js-error)
				       (js-new %this js-error
					  (js-string->jsstring err)))
				    err))))
		       (js-function-arity 0 0)
		       (js-function-info :name "error.get" :len 0))
	       :set (js-make-function %this
		       (lambda (this v)
			  (with-access::JsSSLConnection this (ssl)
			     (with-access::ssl-connection ssl (err)
				(if (js-jsstring? v)
				    (set! err (js-jsstring->string v))
				    (set! err #f)))))
		       (js-function-arity 1 0)
		       (js-function-info :name "error.set" :len 0)))
	    conn)))
   
   (define (check-entropy)
      (let loop ()
	 (unless (ssl-rand-status)
	    (unless (ssl-rand-poll)))))
   
   (define (randomBytes this size cb)
      (check-entropy)
      (cond
	 ((not (number? size))
	  (js-raise-type-error %this "Bad argument" size))
	 ((or (< size 0) (> size 1073741823.))
	  (js-raise-type-error %this "Bad size" size))
	 (else
	  (let ((buf (js-string->jsslowbuffer
			(ssl-rand-bytes (js-tointeger size %this))
			%this)))
	     (if (js-procedure? cb)
		 (!js-callback2 "randomBytes" %worker %this
		    cb this (js-undefined) buf)
		 buf)))))
   
   (define (pseudoRandomBytes this size cb)
      (check-entropy)
      (cond
	 ((not (number? size))
	  (js-raise-type-error %this "Bad argument" size))
	 ((or (< size 0) (> size 1073741823.))
	  (js-raise-type-error %this "Bad size" size))
	 (else
	  (let ((buf (js-string->jsslowbuffer
			(ssl-rand-pseudo-bytes size)
			%this)))
	     (if (js-procedure? cb)
		 (!js-callback2 "pseudoRandomBytes" %worker %this
		    cb this (js-undefined) buf)
		 buf)))))
   
   (define (get-ssl-ciphers this)
      (let ((v (ssl-get-ciphers)))
	 (js-vector->jsarray
	    (vector-map! js-string->jsstring v) %this)))
   
   (define (get-ciphers this)
      (let ((v (evp-get-ciphers)))
	 (js-vector->jsarray
	    (vector-map! js-string->jsstring (list->vector v)) %this)))
   
   (define (get-hashes this)
      (let ((v (evp-get-hashes)))
	 (js-vector->jsarray
	    (vector-map! js-string->jsstring (list->vector v)) %this)))
   
   ;; diffie-hellman
   (define (dh-set-private-key this buffer)
      (with-access::JsDH this (initp dh)
	 (if (not initp)
	     (js-raise-error %this "Not initialize" this)
	     (with-access::dh dh (private-key)
		(set! private-key
		   (bn-bin2bn
		      (buf->string buffer "dh-set-private-key" %this)))))))
   
   (define (dh-set-public-key this buffer)
      (with-access::JsDH this (initp dh)
	 (if (not initp)
	     (js-raise-error %this "Not initialize" this))
	 (with-access::dh dh (public-key)
	    (set! public-key
	       (bn-bin2bn
		  (buf->string buffer "dh-set-public-key" %this))))))
   
   (define (dh-generate-keys this)
      (with-access::JsDH this (initp dh)
	 (unless initp
	    (js-raise-error %this "Not initialize" this))
	 (unless (dh-generate-key dh)
	    (js-raise-error %this "Key generation failed" this))
	 (with-access::dh dh (public-key)
	    (js-string->jsslowbuffer (bn-bn2bin public-key) %this))))
   
   (define (dh-compute-secret this buffer)
      (with-access::JsDH this (initp dh)
	 (unless initp
	    (js-raise-error %this "Not initialize" this))
	 (let* ((str (buf->string buffer "dh-compute-secret" %this))
		(key (bn-bin2bn str))
		(data (dh-compute-key dh key)))
	    (unwind-protect
	       (if (string? data)
		   (js-string->jsslowbuffer data %this)
		   (case (dh-check-pub-key dh key)
		      ((DH-CHECK-PUBKEY-TOO-SMALL)
		       (js-raise-error %this "Supplied key is too small" key))
		      ((DH-CHECK-PUBKEY-TOO-LARGE)
		       (js-raise-error %this "Supplied key is too large" key))
		      (else
		       (js-raise-error %this "Invalid key" this))))
	       (begin
		  (ssl-clear-error)
		  (bn-free key))))))
   
   (define (dh-get-prime this)
      (with-access::JsDH this (initp dh)
	 (unless initp
	    (js-raise-error %this "Not initialize" this))
	 (with-access::dh dh (p)
	    (js-string->jsslowbuffer (bn-bn2bin p) %this))))
   
   (define (dh-get-public-key this)
      (with-access::JsDH this (initp dh)
	 (unless initp
	    (js-raise-error %this "Not initialize" this))
	 (with-access::dh dh (public-key)
	    (js-string->jsslowbuffer (bn-bn2bin public-key) %this))))
   
   (define (dh-get-private-key this)
      (with-access::JsDH this (initp dh)
	 (unless initp
	    (js-raise-error %this "Not initialize" this))
	 (with-access::dh dh (private-key)
	    (js-string->jsslowbuffer (bn-bn2bin private-key) %this))))
   
   (define (dh-get-generator this)
      (with-access::JsDH this (initp dh)
	 (unless initp
	    (js-raise-error %this "Not initialize" this))
	 (with-access::dh dh (g)
	    (js-string->jsslowbuffer (bn-bn2bin g) %this))))
   
   (define diffie-hellman-proto
      (let ((proto (with-access::JsGlobalObject %this (js-object)
		      (js-new %this js-object))))
	 (js-put! proto (& "setPrivateKey")
	    (js-make-function %this dh-set-private-key
	       (js-function-arity dh-set-private-key)
	       (js-function-info :name "setPrivateKey" :len 1))
	    #f %this)
	 (js-put! proto (& "setPublicKey")
	    (js-make-function %this dh-set-public-key
	       (js-function-arity dh-set-public-key)
	       (js-function-info :name "setPublicKey" :len 1))
	    #f %this)
	 (js-put! proto (& "generateKeys")
	    (js-make-function %this dh-generate-keys
	       (js-function-arity dh-generate-keys)
	       (js-function-info :name "generateKeys" :len 0))
	    #f %this)
	 (js-put! proto (& "computeSecret")
	    (js-make-function %this dh-compute-secret
	       (js-function-arity dh-compute-secret)
	       (js-function-info :name "computeSecret" :len 1))
	    #f %this)
	 (js-put! proto (& "getPrime")
	    (js-make-function %this dh-get-prime
	       (js-function-arity dh-get-prime)
	       (js-function-info :name "getPrime" :len 0))
	    #f %this)
	 (js-put! proto (& "getPublicKey")
	    (js-make-function %this dh-get-public-key
	       (js-function-arity dh-get-public-key)
	       (js-function-info :name "getPublicKey" :len 0))
	    #f %this)
	 (js-put! proto (& "getPrivateKey")
	    (js-make-function %this dh-get-private-key
	       (js-function-arity dh-get-private-key)
	       (js-function-info :name "getPrivateKey" :len 0))
	    #f %this)
	 (js-put! proto (& "getGenerator")
	    (js-make-function %this dh-get-generator
	       (js-function-arity dh-get-generator)
	       (js-function-info :name "getGenerator" :len 1))
	    #f %this)
	 proto))
   
   (define (diffie-hellman-string dh obj str)
      (with-access::dh dh (p g)
	 (set! p (bn-bin2bn str))
	 (set! g (bn-new))
	 (when (bn-set-word g 2)
	    (cond
	       ((dh-check dh)
		=>
		(lambda (m)
		   (js-raise-error %this
		      (format "Initialization failed (~a)" m) dh)))
	       (else
		(with-access::JsDH obj (initp)
		   (set! initp #t)))))
	 obj))
   
   (define (diffie-hellman-string2 dh obj str str2)
      (with-access::dh dh (p g)
	 (set! p (bn-bin2bn str))
	 (set! g (bn-bin2bn str2))
	 (with-access::JsDH obj (initp)
	    (set! initp #t))
	 obj))
   
   (define (diffie-hellman this . args)
      (let* ((dh (instantiate::dh))
	     (obj (instantiateJsDH
		     (__proto__ diffie-hellman-proto)
		     (dh dh))))
	 (cond
	    ((integer? (car args))
	     (dh-generate-parameters-ex dh (car args) 'DH-GENERATOR-2)
	     (unless (dh-check dh)
		(with-access::JsDH obj (initp) (set! initp #t))))
	    ((isa? (car args) JsSlowBuffer)
	     (diffie-hellman-string dh obj
		(js-jsslowbuffer->string (car args))))
	    ((isa? (car args) JsFastBuffer)
	     (diffie-hellman-string dh obj
		(js-jsfastbuffer->string (car args))))
	    ((pair? (car args))
	     (diffie-hellman-string2 dh obj (caar args) (cdar args)))
	    (else
	     (js-raise-error %this
		(format "Wrong initialization value (~a)" (typeof (car args)))
		(car args))))
	 obj))
   
   (define (diffie-hellman-group this group-name)
      (unless (js-jsstring? group-name)
	 (js-raise-type-error %this
	    (format "Bad parameter ~a" (typeof group-name))
	    group-name))
      (let* ((name (js-jsstring->string group-name))
	     (buf (assoc name modp_groups)))
	 (if buf
	     (diffie-hellman this (cadr buf))
	     (error "diffie-hellman-group" "todo" group-name))))
   
   ;; hmac
   (define (hmac-init this type key)
      (if (not (js-jsstring? type))
	  (js-raise-type-error %this
	     "Must be given hashtype string as argument" type)
	  (let ((key (buf->string key "hmac-init" %this)))
	     (with-access::JsHmac this (hmac)
		(ssl-hmac-init hmac (js-jsstring->string type) key)
		this))))
   
   (define (hmac-update this data)
      (with-access::JsHmac this (hmac)
	 (multiple-value-bind (s offset len)
	    (data->string data "hmac-update" %this)
	    (ssl-hmac-update! hmac s offset len)
	    this)))
   
   (define (hmac-digest this enc)
      (with-access::JsHmac this (hmac)
	 (string-encode %this (ssl-hmac-digest hmac) enc)))
   
   (define hmac-proto
      (let ((proto (with-access::JsGlobalObject %this (js-object)
		      (js-new %this js-object))))
	 (js-put! proto (& "init")
	    (js-make-function %this hmac-init
	       (js-function-arity hmac-init)
	       (js-function-info :name "init" :len 1))
	    #f %this)
	 (js-put! proto (& "update")
	    (js-make-function %this hmac-update
	       (js-function-arity hmac-update)
	       (js-function-info :name "update" :len 1))
	    #f %this)
	 (js-put! proto (& "digest")
	    (js-make-function %this hmac-digest
	       (js-function-arity hmac-digest)
	       (js-function-info :name "digest" :len 1))
	    #f %this)
	 proto))
   
   (define (hmac this type data)
      (instantiateJsHmac
	 (__proto__ hmac-proto)
	 (hmac (instantiate::ssl-hmac))))
   
   ;; hash
   (define (hash-update this data enc)
      (with-access::JsHash this (hash)
	 (if (eq? enc (js-undefined))
	     (multiple-value-bind (s offset len)
		(data->string data "hash-update" %this)
		(ssl-hash-update! hash s offset len))
	     (let* ((s (buf->string data "hash-update" %this))
		    (str (string-decode s enc %this)))
		(ssl-hash-update! hash str 0 (string-length str))))))
   
   (define (hash-digest this enc)
      (with-access::JsHash this (hash)
	 (string-encode %this (ssl-hash-digest hash) enc)))
   
   (define hash-proto
      (let ((proto (with-access::JsGlobalObject %this (js-object)
		      (js-new %this js-object))))
	 (js-put! proto (& "update")
	    (js-make-function %this hash-update
	       (js-function-arity hash-update)
	       (js-function-info :name "update" :len 1))
	    #f %this)
	 (js-put! proto (& "digest")
	    (js-make-function %this hash-digest
	       (js-function-arity hash-digest)
	       (js-function-info :name "digest" :len 1))
	    #f %this)
	 proto))
   
   (define (hash this type)
      (instantiateJsHash
	 (__proto__ hash-proto)
	 (hash (instantiate::ssl-hash
		  (type (js-jsstring->string type))))))
   
   ;; sign
   (define (sign-init this type)
      (if (not (js-jsstring? type))
	  (js-raise-type-error %this
	     "Must be given signtype string as argument" type)
	  (with-access::JsSign this (sign)
	     (ssl-sign-init sign (js-jsstring->string type))
	     this)))
   
   (define (sign-update this data enc)
      (with-access::JsSign this (sign)
	 (if (eq? enc (js-undefined))
	     (multiple-value-bind (s offset len)
		(data->string data "sign-update" %this)
		(ssl-sign-update! sign s offset len))
	     (let* ((s (buf->string data "sign-update" %this))
		    (str (string-decode s enc %this)))
		(ssl-sign-update! sign str 0 (string-length str))))))
   
   (define (sign-sign this data enc)
      (with-access::JsSign this (sign)
	 (multiple-value-bind (s offset len)
	    (data->string data "sign-sign" %this)
	    (string-encode %this (ssl-sign-sign sign s offset len) enc))))
   
   (define sign-proto
      (let ((proto (with-access::JsGlobalObject %this (js-object)
		      (js-new %this js-object))))
	 (js-put! proto (& "init")
	    (js-make-function %this sign-init
	       (js-function-arity sign-init)
	       (js-function-info :name "init" :len 1))
	    #f %this)
	 (js-put! proto (& "update")
	    (js-make-function %this sign-update
	       (js-function-arity sign-update)
	       (js-function-info :name "update" :len 1))
	    #f %this)
	 (js-put! proto (& "sign")
	    (js-make-function %this sign-sign
	       (js-function-arity sign-sign)
	       (js-function-info :name "sign" :len 1))
	    #f %this)
	 proto))
   
   (define (sign this)
      (instantiateJsSign
	 (__proto__ sign-proto)
	 (sign (instantiate::ssl-sign))))
   
   ;; verify
   (define (verify-init this type)
      (if (not (js-jsstring? type))
	  (js-raise-type-error %this
	     "Must be given verifytype string as argument" type)
	  (with-access::JsVerify this (verify)
	     (ssl-verify-init verify (js-jsstring->string type))
	     this)))
   
   (define (verify-update this data enc)
      (with-access::JsVerify this (verify)
	 (if (eq? enc (js-undefined))
	     (multiple-value-bind (s offset len)
		(data->string data "verify-update" %this)
		(ssl-verify-update! verify s offset len))
	     (let* ((s (buf->string data "verify-update" %this))
		    (str (string-decode s enc %this)))
		(ssl-verify-update! verify str 0 (string-length str))))))
   
   (define (verify-final this data sig enc)
      (with-access::JsVerify this (verify)
	 (multiple-value-bind (ds doffset dlen)
	    (data->string data "verify-verify" %this)
	    (multiple-value-bind (ss soffset slen)
	       (data->string sig "verify-verify" %this)
	       (ssl-verify-final verify
		  ds doffset dlen
		  ss soffset slen)))))
   
   (define verify-proto
      (let ((proto (with-access::JsGlobalObject %this (js-object)
		      (js-new %this js-object))))
	 (js-put! proto (& "init")
	    (js-make-function %this verify-init
	       (js-function-arity verify-init)
	       (js-function-info :name "init" :len 1))
	    #f %this)
	 (js-put! proto (& "update")
	    (js-make-function %this verify-update
	       (js-function-arity verify-update)
	       (js-function-info :name "update" :len 1))
	    #f %this)
	 (js-put! proto (& "verify")
	    (js-make-function %this verify-final
	       (js-function-arity verify-final)
	       (js-function-info :name "verify" :len 1))
	    #f %this)
	 proto))
   
   (define (verify this)
      (instantiateJsVerify
	 (__proto__ verify-proto)
	 (verify (instantiate::ssl-verify))))
   
   ;; cipher
   (define (cipher-init this type key)
      (with-access::JsCipher this (cipher)
	 (if (not (js-jsstring? type))
	     (js-raise-type-error %this
		"Must be given cipher type string as argument" type)
	     (multiple-value-bind (s offset len)
		(data->string key "cipher-init" %this)
		(ssl-cipher-init cipher (js-jsstring->string type)
		   s offset len
		   (not (isa? this JsDecipher)))))))
   
   (define (cipher-initiv this type key iv)
      (with-access::JsCipher this (cipher)
	 (if (not (js-jsstring? type))
	     (js-raise-type-error %this
		"Cipher must be given cipher type string as argument" type)
	     (multiple-value-bind (ks koffset klen)
		(data->string key "cipher-initiv" %this)
		(multiple-value-bind (is ioffset ilen)
		   (data->string iv "cipher-initiv" %this)
		   (ssl-cipher-initiv cipher (js-jsstring->string type)
		      ks koffset klen
		      is ioffset ilen
		      (not (isa? this JsDecipher))))))))
   
   (define (cipher-update this data ienc oenc)
      (with-access::JsCipher this (cipher)
	 ;; this function should be rewritten to avoid allocating
	 ;; so many auxiliary strings
	 (let* ((s (buf->string data "cipher-update" %this))
		(str (string-decode s ienc %this))
		(so (ssl-cipher-update! cipher str 0 (string-length str))))
	    (string-encode %this so (& "buffer")))))
   
   (define (cipher-final this enc)
      (with-access::JsCipher this (cipher)
	 (with-handler
	    (lambda (e)
	       (exception-notify e)
	       (with-access::&error e (msg)
		  (js-raise-type-error %this msg e)))
	    (string-encode %this (ssl-cipher-final cipher) enc))))
   
   (define (cipher-set-auto-padding this ap)
      (with-access::JsCipher this (cipher)
	 (ssl-cipher-set-auto-padding cipher ap)))
   
   (define cipher-proto
      (let ((proto (with-access::JsGlobalObject %this (js-object)
		      (js-new %this js-object))))
	 (js-put! proto (& "init")
	    (js-make-function %this cipher-init
	       (js-function-arity cipher-init)
	       (js-function-info :name "init" :len 1))
	    #f %this)
	 (js-put! proto (& "initiv")
	    (js-make-function %this cipher-initiv
	       (js-function-arity cipher-initiv)
	       (js-function-info :name "initiv" :len 1))
	    #f %this)
	 (js-put! proto (& "update")
	    (js-make-function %this cipher-update
	       (js-function-arity cipher-update)
	       (js-function-info :name "update" :len 3))
	    #f %this)
	 (js-put! proto (& "final")
	    (js-make-function %this cipher-final
	       (js-function-arity cipher-final)
	       (js-function-info :name "final" :len 1))
	    #f %this)
	 (js-put! proto (& "setAutoPadding")
	    (js-make-function %this cipher-set-auto-padding
	       (js-function-arity cipher-set-auto-padding)
	       (js-function-info :name "setAutoPadding" :len 1))
	    #f %this)
	 proto))
   
   (define decipher-proto
      (let ((proto (with-access::JsGlobalObject %this (js-object)
		      (js-new %this js-object))))
	 (js-object-proto-set! proto decipher-proto)
	 (js-put! proto (& "init")
	    (js-make-function %this cipher-init
	       (js-function-arity cipher-init)
	       (js-function-info :name "init" :len 1))
	    #f %this)
	 (js-put! proto (& "initiv")
	    (js-make-function %this cipher-initiv
	       (js-function-arity cipher-initiv)
	       (js-function-info :name "initv" :len 1))
	    #f %this)
	 (js-put! proto (& "update")
	    (js-make-function %this cipher-update
	       (js-function-arity cipher-update)
	       (js-function-info :name "update" :len 1))
	    #f %this)
	 (js-put! proto (& "final")
	    (js-make-function %this cipher-final
	       (js-function-arity cipher-final)
	       (js-function-info :name "final" :len 1))
	    #f %this)
	 (js-put! proto (& "finaltol")
	    (js-make-function %this cipher-final
	       (js-function-arity cipher-final)
	       (js-function-info :name "finaltol" :len 1))
	    #f %this)
	 (js-put! proto (& "setAutoPadding")
	    (js-make-function %this cipher-set-auto-padding
	       (js-function-arity cipher-set-auto-padding)
	       (js-function-info :name "setAutoPadding" :len 1))
	    #f %this)
	 proto))
   
   (define (cipher this)
      (instantiateJsCipher
	 (__proto__ cipher-proto)
	 (cipher (instantiate::ssl-cipher))))
   
   (define (decipher this)
      (instantiateJsDecipher
	 (__proto__ decipher-proto)
	 (cipher (instantiate::ssl-cipher))))
   
   ;; pbkdf2
   (define (pbkdf2 this password salt iterations keylen callback)
      (with-access::JsGlobalObject %this (js-object)
	 (with-handler
	    (lambda (err)
	       (if (js-procedure? callback)
		   (let ((obj (js-new %this js-object)))
		      (js-put! obj (& "ondone") callback #f %this)
		      (js-call2 %this callback obj err (js-undefined)))
		   (raise err)))
	    (let ((r (string-encode %this
			(pkcs5-pbkdf2-hmac-sha1
			   (buf->string password "pbkdf2" %this)
			   (buf->string salt "pbkdf2" %this)
			   iterations
			   keylen)
			(js-undefined))))
	       (if (js-procedure? callback)
		   (let ((obj (js-new %this js-object)))
		      (js-put! obj (& "ondone") callback #f %this)
		      (js-call2 %this callback obj (js-undefined) r))
		   r)))))
   
   (let ((sc (js-make-function %this secure-context
		(js-function-arity secure-context)
		(js-function-info :name "SecureContext" :len 1)
		:alloc js-no-alloc
		:prototype secure-context-proto))
	 (conn (js-make-function %this connection
		  (js-function-arity connection)
		  (js-function-info :name "Connection" :len 1)
		  :alloc js-no-alloc
		  :prototype connection-proto))
	 (dh (js-make-function %this diffie-hellman
		(js-function-arity diffie-hellman)
		(js-function-info :name "DiffieHellman" :len 1)
		:alloc js-no-alloc
		:prototype diffie-hellman-proto))
	 (dhg (js-make-function %this diffie-hellman-group
		 (js-function-arity diffie-hellman-group)
		 (js-function-info :name "DiffieHellmanGroup" :len 1)
		 :alloc js-no-alloc
		 :prototype diffie-hellman-proto))
	 (hm (js-make-function %this hmac
		(js-function-arity hmac)
		(js-function-info :name "Hmac" :len 1)
		:alloc js-no-alloc
		:prototype hmac-proto))
	 (hs (js-make-function %this hash
		(js-function-arity hash)
		(js-function-info :name "Hash" :len 1)
		:alloc js-no-alloc
		:prototype hash-proto))
	 (sn (js-make-function %this sign
		(js-function-arity sign)
		(js-function-info :name "Sign" :len 1)
		:alloc js-no-alloc
		:prototype sign-proto))
	 (vf (js-make-function %this verify
		(js-function-arity sign)
		(js-function-info :name "Verify" :len 1)
		:alloc js-no-alloc
		:prototype verify-proto))
	 (ci (js-make-function %this cipher
		(js-function-arity sign)
		(js-function-info :name "cipher" :len 1)
		:alloc js-no-alloc
		:prototype cipher-proto))
	 (dc (js-make-function %this decipher
		(js-function-arity sign)
		(js-function-info :name "decipher" :len 1)
		:alloc js-no-alloc
		:prototype decipher-proto)))
      
      (with-access::JsGlobalObject %this (js-object)
	 (js-alist->jsobject
	    `((SecureContext . ,sc)
	      (Connection . ,conn)
	      (Cipher . ,ci)
	      (Decipher . ,dc)
	      (DiffieHellman . ,dh)
	      (DiffieHellmanGroup . ,dhg)
	      (Hmac . ,hm)
	      (Hash . ,hs)
	      (Sign . ,sn)
	      (Verify . ,vf)
	      
	      (PBKDF2 . ,(js-make-function %this pbkdf2
			    (js-function-arity pbkdf2)
			    (js-function-info :name "pbkdf2" :len 5)))
	      (randomBytes . ,(js-make-function %this randomBytes
				 (js-function-arity randomBytes)
				 (js-function-info :name "randomBytes" :len 2)))
	      (pseudoRandomBytes . ,(js-make-function %this pseudoRandomBytes
				       (js-function-arity pseudoRandomBytes)
				       (js-function-info :name "pseudoRandomBytes" :len 2)))
	      (getSSLCiphers . ,(js-make-function %this get-ssl-ciphers
				   (js-function-arity get-ssl-ciphers)
				   (js-function-info :name "getSSLCiphers" :len 0)))
	      (getCiphers . ,(js-make-function %this get-ciphers
				(js-function-arity get-ciphers)
				(js-function-info :name "getCiphers" :len 0)))
	      (getHashes . ,(js-make-function %this get-hashes
			       (js-function-arity get-hashes)
			       (js-function-info :name "getHashes" :len 0))))
	    %this))))

;*---------------------------------------------------------------------*/
;*    string-encode ...                                                */
;*---------------------------------------------------------------------*/
(define (string-encode %this data encoding)
   (cond
      ((eq? encoding (js-undefined))
       (js-string->jsfastbuffer data %this))
      ((js-jsstring? encoding)
       (case (string->symbol (js-jsstring->string encoding))
	  ((buffer)
	   (js-string->jsfastbuffer data %this))
	  ((hex)
	   (js-string->jsstring
	      (string-hex-extern data 0 (string-length data))))
	  ((ucs2)
	   (js-string->jsstring
	      (string->ucs2-string data 0 (string-length data))))
	  ((base64)
	   (let ((ip (open-input-string! data 0 (string-length data)))
		 (op (open-output-string)))
	      (base64-encode-port ip op 0)
	      (js-string->jsstring
		 (close-output-port op))))
	  ((ascii)
	   (let* ((len (string-length data))
		  (string (make-string len)))
	      (when (>fx len 0)
		 (blit-string-ascii-clamp! data 0 string 0 len))
	      (js-string->jsstring string)))
	  ((utf8 utf-8)
	   (string-utf8-normalize-utf16 data 0 (string-length data)))
	  ((binary)
	   (js-string->jsstring
	      (8bits-encode-utf8 data 0 (string-length data))))
	  (else
	   (error "crypto" "bad encoding" encoding))))
      (else
       (error "crypto" "bad encoding" encoding))))

;*---------------------------------------------------------------------*/
;*    string-decode ...                                                */
;*---------------------------------------------------------------------*/
(define (string-decode data encoding %this)
   (cond
      ((eq? encoding (js-undefined))
       data)
      ((js-jsstring? encoding)
       (case (string->symbol (js-jsstring->string encoding))
	  ((buffer)
	   data)
	  ((hex)
	   (if (oddfx? (string-length data))
	       (js-raise-type-error %this "Bad input string" data)
	       (string-hex-intern data)))
	  ((ucs2)
	   (string->ucs2-string data 0 (string-length data)))
	  ((base64)
	   (base64-decode data #f))
	  ((ascii)
	   data)
	  ((utf8 utf-8)
	   data)
	  ((binary)
	   data)
	  (else
	   (error "crypto" "bad encoding" encoding))))
      (else
       (error "crypto" "bad encoding" encoding))))

;*---------------------------------------------------------------------*/
;*    Hello-Parser Constants                                           */
;*---------------------------------------------------------------------*/
(define (kClientHello) #a001)

(define (kChangeCipherSpec) #a020)
(define (kAlert) #a021)
(define (kHandshake) #a022)
(define (kApplicationData) #a023)
(define (kOther) #a255)

;*---------------------------------------------------------------------*/
;*    kBufferSize ...                                                  */
;*---------------------------------------------------------------------*/
(define (kBufferSize data)
   (string-length data))

;*---------------------------------------------------------------------*/
;*    iref ...                                                         */
;*---------------------------------------------------------------------*/
(define (iref str idx)
   (char->integer (string-ref-ur str idx)))

;*---------------------------------------------------------------------*/
;*    hello-parser-ended ...                                           */
;*---------------------------------------------------------------------*/
(define (hello-parser-ended hparser::HelloParser)
   (with-access::HelloParser hparser (state)
      (eq? state 'kEnded)))

;*---------------------------------------------------------------------*/
;*    hello-parser-finish ...                                          */
;*    -------------------------------------------------------------    */
;*    See node_crypto.cc ClientHelloParser::Finish                     */
;*---------------------------------------------------------------------*/
(define (hello-parser-finish hparser::HelloParser)
   (with-access::HelloParser hparser (state data conn offset)
      (with-access::JsSSLConnection conn (ssl)
	 (when (>fx debug-crypto 0)
	    (tprint "BIO_write.1 offset=" offset))
	 (ssl-connection-write ssl data 0 offset))
      (set! state 'kEnded)
      (set! data "")))
   
;*---------------------------------------------------------------------*/
;*    hello-parser-write ...                                           */
;*    -------------------------------------------------------------    */
;*    See src/node_crypto.cc ClientHelloParser::Write                  */
;*---------------------------------------------------------------------*/
(define (hello-parser-write hparser::HelloParser
	   buffer::bstring offset::long len::long)
   (with-access::HelloParser hparser (state (data_ data) (offset_ offset) conn
					frame-len body-offset)
      (when (>fx debug-crypto 0)
	 (tprint "HelloParser state=" state))
      (if (eq? state 'kPaused)
	  0
	  (let* ((available (-fx (kBufferSize data_) offset_))
		 (copied (if (<fx len available) len available))
		 (is-clienthello #f)
		 (session-size -1)
		 (session-id-offset 0))
	     (blit-string! buffer offset data_ offset_ copied)
	     (when (>fx debug-crypto 0)
		(tprint "HelloParser avail=" available " copied=" copied " offset=" offset_ )
		(tprint "data_="
		   (iref data_ offset_) " " 
		   (iref data_ (+fx 1 offset_)) " " 
		   (iref data_ (+fx 2 offset_)) " " 
		   (iref data_ (+fx 3 offset_)) " " 
		   (iref data_ (+fx 4 offset_)) " " 
		   (iref data_ (+fx 5 offset_)))
		(tprint "buffer="
		   (iref buffer 0) " " 
		   (iref buffer (+fx 1 0)) " " 
		   (iref buffer (+fx 2 0)) " " 
		   (iref buffer (+fx 3 0)) " " 
		   (iref buffer (+fx 4 0)) " " 
		   (iref buffer (+fx 5 0))))
	     (set! offset_ (+fx offset_ copied))
	     (let loop ()
		(case state
		   ((kWaiting)
		    (when (>fx debug-crypto 0)
		       (tprint "HelloParser state.2=" state))
		    (if (<fx offset_ 5)
			;; >= 5 bytes for header parsing
			copied
			(begin
			   (if (or (char=? (string-ref data_ 0) (kChangeCipherSpec))
				   (char=? (string-ref data_ 0) (kHandshake))
				   (char=? (string-ref data_ 0) (kApplicationData)))
			       (begin
				  (set! frame-len
				     (+fx (bit-lsh (iref data_ 3) 8) (iref data_ 4)))
				  (set! state 'kTLSHeader)
				  (set! body-offset 5))
			       (begin
				  (set! frame-len
				     (+fx (bit-lsh (iref data_ 0) 8) (iref data_ 1)))
				  (set! state 'kSSLHeader)
				  (if (=fx (bit-and (iref data_ 0) #x40) 0)
				      ;; no padding
				      (set! body-offset 2)
				      ;; padding
				      (set! body-offset 3))))

			   (when (>fx debug-crypto 0)
			      (tprint "HelloParser frame_len=" frame-len
				 " body_offset=" body-offset))
			   ;; Sanity check (too big frame, or too small)
			   (if (>= frame-len (kBufferSize data_))
			       (begin
				  ;; Let OpenSSL handle it
				  (hello-parser-finish hparser)
				  copied)
			       (loop)))))
		   ((kTLSHeader kSSLHeader)
		    (when (>fx debug-crypto 0)
		       (tprint "HelloParser state.3=" state
			  " offset=" offset_ " body+frame=" (+fx body-offset frame-len)))
		    ;; >= 5 + frame size bytes for frame parsing
		    (if (<fx offset_ (+fx body-offset frame-len))
			copied
			(begin
			   ;; Skip unsupported frames and gather some data from frame
			   ;; TODO: Check protocol version
			   (when (char=? (string-ref data_ body-offset) (kClientHello))
			      (set! is-clienthello #t)
			      (case state
				 ((kTLSHeader)
				  ;; Skip frame header, hello header, protocol version and random data
				  (let ((session-offset (+fx body-offset (+fx 4 (+fx 2 32)))))
				     (if (<fx (+fx session-offset 1) offset_)
					 (begin
					    (set! session-size (iref data_ session-offset))
					    (set! session-id-offset (+fx session-offset 1))))
				     (when (>fx debug-crypto 0)
					(tprint "HelloParser == kClientHello, state=" state
					   " session-offset=" session-offset
					   " session-size=" session-size
					   " session-id-offset=" session-id-offset))))
				 ((kSSLHeader)
				  ;; Skip header, version
				  (let ((session-offset (+fx body-offset 3)))
				     (if (<fx (+fx session-offset 4) offset_)
					 (let ((ciphers-size
						  (+fx (bit-lsh (iref data_ session-offset) 8)
						     (iref data_ (+fx session-offset 1)))))
					    (when (<fx (+fx session-offset (+fx 4 ciphers-size)) offset_)
					       (set! session-size
						  (+fx (bit-lsh (iref data_ (+fx session-offset 2)) 8)
						     (iref data_ (+fx session-offset 3))))
					       (set! session-id-offset
						  (+fx session-offset (+fx 4 ciphers-size))))))))
				 (else
				  ;; Whoa? How did we get here?
				  (error "crypto" "bad state" state)))
			      
			      ;; Check if we overflowed (do not reply with any private data)
			      (if (or (=fx session-id-offset 0)
				      (>fx session-size 32)
				      (>fx (+fx session-id-offset session-size) offset_))
				  (begin
				     (hello-parser-finish hparser)
				     copied))
			      ;; TODO: Parse other things?
			      )

			   ;; Not client hello - let OpenSSL handle it
			   (if (not is-clienthello)
			       (begin
				  (hello-parser-finish hparser)
				  copied)
			       (with-access::HelloParser hparser (%this %worker)
				  (with-access::JsGlobalObject %this (js-object)
				     (let ((hello (js-new %this js-object))
					   (buffer (js-string->jsfastbuffer data_ %this))
					   (onclienthello (js-get conn (& "onclienthello") %this)))
					;; Parse frame, call javascript handler and
					;; move parser into the paused state
					(with-access::JsFastBuffer buffer (byteoffset length)
					   (set! byteoffset (fixnum->uint32 session-id-offset))
					   (set! length (fixnum->uint32 session-size))
					   (js-put! buffer (& "length") session-size #f %this)
					   (js-put! hello (& "sessionId") buffer #f %this)
					   (set! state 'kPaused)
					   (when (>fx debug-crypto 0)
					      (tprint "HelloParser session_size=" session-size
						 " callback "
						 (iref data_ (+fx (uint32->fixnum byteoffset) 0)) " " 
						 (iref data_ (+fx (uint32->fixnum byteoffset) 1)) " " 
						 (iref data_ (+fx (uint32->fixnum byteoffset) 2)) " " 
						 (iref data_ (+fx (uint32->fixnum byteoffset) 3))
						 " => copied=" copied)))
					(!js-callback1 "HelloParser" %worker %this
					   onclienthello conn hello)
					copied)))))))
		   (else
		    copied)))))))

;*---------------------------------------------------------------------*/
;*    data->string ...                                                 */
;*---------------------------------------------------------------------*/
(define (data->string buf proc %this::JsGlobalObject)
   (cond
      ((js-jsstring? buf)
       (let ((s (js-jsstring->string buf)))
	  (values s 0 (string-length s))))
      ((isa? buf JsFastBuffer)
       (with-access::JsFastBuffer buf (%data byteoffset length)
	  (let ((start (uint32->fixnum byteoffset))
		(len (uint32->fixnum length)))
	     (values %data start len))))
      ((isa? buf JsSlowBuffer)
       (with-access::JsSlowBuffer buf (data)
	  (values data 0 (string-length data))))
      (else
       (js-raise-type-error %this
	  (string-append proc ": Not a string or buffer (" (typeof buf) ")") buf))))

;*---------------------------------------------------------------------*/
;*    &end!                                                            */
;*---------------------------------------------------------------------*/
(&end!)

;*---------------------------------------------------------------------*/
;*    no ssl support                                                   */
;*---------------------------------------------------------------------*/
)
(else
 (define (crypto-constants) '())
 (define (process-crypto %worker %this)
    #unspecified)))

;*---------------------------------------------------------------------*/
;*    buf->string ...                                                  */
;*---------------------------------------------------------------------*/
(define (buf->string buf proc %this::JsGlobalObject)
   (cond
      ((isa? buf JsStringLiteralUTF8)
       (utf8->iso-latin (js-jsstring->string buf)))
      ((js-jsstring? buf)
       (js-jsstring->string buf))
      ((isa? buf JsFastBuffer)
       (js-jsfastbuffer->string buf))
      ((isa? buf JsSlowBuffer)
       (js-jsslowbuffer->string buf))
      (else
       (js-raise-type-error %this
	  (string-append proc ": Not a string or buffer") buf))))
