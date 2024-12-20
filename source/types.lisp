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
(cl:in-package #:double-ratchet)


(defclass state ()
  ((%chain-key-receive
    :initarg :chain-key-receive
    :initform nil
    :accessor ckr
    :accessor chain-key-receive)
   (%number-of-received-messages
    :accessor number-of-received-messages
    :initarg :number-of-received-messages)
   (%constant
    :initarg :constant
    :reader constant)))

(defclass ratchet ()
  ((%root-key
    :initarg :root-key
    :accessor root-key
    :accessor rk)
   (%sending-keys
    :initform nil
    :initarg :sending-keys
    :accessor sending-keys)
   (%received-key
    :initarg :received-key
    :initform nil
    :accessor received-key)
   (%chain-key-receive
    :initarg :chain-key-receive
    :initform nil
    :accessor ckr
    :accessor chain-key-receive)
   (%chain-key-send
    :initarg :chain-key-send
    :initform nil
    :accessor cks
    :accessor chain-key-send)
   (%number-of-sent-messages
    :initarg :number-of-sent-messages
    :initform nil
    :accessor number-of-sent-messages)
   (%number-of-received-messages
    :accessor number-of-received-messages
    :initarg :number-of-received-messages)
   (%number-of-messages-in-previous-sending-chain
    :accessor number-of-messages-in-previous-sending-chain
    :initarg :number-of-messages-in-previous-sending-chain
    :initform 0)
   (%constant
    :initarg :constant
    :reader constant))
  (:default-initargs
   :number-of-sent-messages 0
   :number-of-received-messages 0
   :root-key nil
   :constant (ic:make-random-salt 0)))

(defclass client ()
  ((%lock :initarg :lock
          :reader lock)
   (%other-client-public-key :initarg :other-client-public-key
                             :reader other-client-public-key)
   (%long-term-identity-key :initarg :long-term-identity-key
                            :reader long-term-identity-key)
   (%ephemeral-key-1 :initarg :ephemeral-key-1
                     :accessor ephemeral-key-1)
   (%ephemeral-key-2 :initarg :ephemeral-key-2
                     :accessor ephemeral-key-2)
   (%ephemeral-key-3 :initarg :ephemeral-key-3
                     :accessor ephemeral-key-3)
   (%ephemeral-key-4 :initarg :ephemeral-key-4
                     :accessor ephemeral-key-4)
   (%shared-key :initarg :shared-key
                :reader shared-key)
   (%skipped-messages :initarg :skipped-messages
                      :reader skipped-messages)
   (%ratchet :initarg :ratchet
             :accessor ratchet)
   (%message-class :initarg :message-class
                   :reader message-class))
  (:default-initargs
   :lock (bt2:make-lock)
   :other-client-public-key nil
   :message-class 'message
   :skipped-messages (make-skipped-messages)
   :ratchet nil
   :ephemeral-key-1 (make-25519-private-key)
   :ephemeral-key-2 (make-25519-private-key)
   :ephemeral-key-3 (make-25519-private-key)
   :ephemeral-key-4 (make-25519-private-key)
   :long-term-identity-key (make-25519-private-key)))

(defclass message ()
  ((%sending-key
    :initarg :sending-key
    :reader message-sending-key)
   (%number
    :initarg :number
    :reader message-number)
   (%message-count-in-previous-sending-chain
    :initarg :message-count-in-previous-sending-chain
    :reader message-count-in-previous-sending-chain)
   (%content
    :initarg :content
    :reader read-message-content)
   (%start
    :initarg :start
    :reader message-start)
   (%end
    :initarg :end
    :reader message-end)))

(define-condition cant-encrypt-yet (error)
  ())
