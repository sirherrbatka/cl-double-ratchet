#|
Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1) Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2) Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
|#
(cl:defpackage #:double-ratchet
  (:use #:common-lisp #:metabang.bind #:iterate)
  (:import-from #:serapeum
                #:vector=
                #:make
                #:vect
                #:lret
                #:~>)
  (:local-nicknames
   (#:a #:alexandria)
   (#:ic #:ironclad))
  (:export
   #:make-local-client
   #:make-remote-client
   #:client-public-keys
   #:serial-public-key
   #:serial-private-key
   #:serial-keys-pair
   #:encrypt
   #:make-25519-keys
   #:remote-client
   #:make-double-ratchet
   #:decrypt
   #:x
   #:y
   #:ironclad<-pantalea
   #:pantalea<-ironclad
   #:can-encrypt-p
   #:pkcs7-pad
   #:pkcs7-unpad
   #:long-term-identity-remote-key
   #:make-padded-vector-for-length
   #:make-25519-private-key
   #:make-25519-public-key
   #:long-term-identity-key
   #:private
   #:public))
