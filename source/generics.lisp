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


(defgeneric sending-chain (ratchet))
(defgeneric receiving-chain (ratchet))
(defgeneric kdf (chain))
(defgeneric forward (chain bytes))
(defgeneric steps (chain))
(defgeneric (setf steps) (new-value chain))
(defgeneric key (chain))
(defgeneric (setf key) (new-value chain))
(defgeneric next-key (ratchet &optional inb))
(defgeneric constant (symmetric-key-ratchet))
(defgeneric symetric-key-ratchet (diffie-hellman-ratchet))
(defgeneric private-key (diffie-hellman-ratchet))
(defgeneric public-key (diffie-hellman-ratchet))
(defgeneric derive-public (diffie-hellman-ratchet))
(defgeneric derive-private (diffie-hellman-ratchet))
(defgeneric long-term-identity-key (client))
(defgeneric signed-pre-key (client))
(defgeneric exchange-keys* (this-client other-client))
(defgeneric encrypt* (this-client other-client message start end))
(defgeneric decrypt* (this-client other-client cipher-text start end))
(defgeneric dh-ratchet (this-client
                        public-key
                        number-of-sent-messages
                        number-of-messages-in-previous-sending-chain))
(defgeneric encrypt (double-ratchet message))
(defgeneric decrypt (double-ratchet data))
(defgeneric long-term-identity-remote-key (double-ratchet))
(defgeneric can-encrypt-p (double-ratchet))

(defgeneric message-send-key (message))
(defgeneric message-number (message))
(defgeneric message-count-in-previous-sending-chain (message))
(defgeneric message-content (message))
(defgeneric make-message (class-name &rest rest &key send-key number message-count-in-previous-sending-chain content)
  (:method (class-name &rest rest &key send-key number message-count-in-previous-sending-chain content)
    (declare (ignore send-key number message-count-in-previous-sending-chain content))
    (apply #'make class-name rest)))
(defgeneric message-class (double-ratchet))
(defgeneric clonee (object))
