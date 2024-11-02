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


(defun client-public-keys (client)
  (list (get-public-key (long-term-identity-key client))
        (get-public-key (ephemeral-key-1 client))
        (get-public-key (ephemeral-key-2 client))
        (get-public-key (ephemeral-key-3 client))
        (get-public-key (ephemeral-key-4 client))))

(defun make-client (long-term-identity-key)
  (make-instance 'client
                 :long-term-identity-key long-term-identity-key))

(defun kdf-rk (rk dh-out)
  "Returns a pair (32-byte root key, 32-byte chain key) as the output of applying a KDF keyed by a 32-byte root key rk to a Diffie-Hellman output dh-out."
  (let ((output (ic:derive-key (ic:make-kdf :hmac-kdf :digest :sha256)
                               rk
                               dh-out
                               8
                               64)))
    (values (subseq output 0 32) (subseq output 32))))

(defun kdf-ck (ratchet chain-key)
  "Returns a tuple (32-byte chain key, 32-byte message key, 16-byte initialization vector) as the output of applying a KDF keyed by a 32-byte chain key ck to some constant."
  (let ((output (ic:derive-key (ic:make-kdf :hmac-kdf :digest :sha256)
                               chain-key
                               (constant ratchet)
                               8
                               80)))
    (values (subseq output 0 32) (subseq output 32 64) (subseq output 64))))

(defun decrypt-imlementation (message-key iv ciphertext start end)
  (ic:decrypt-in-place (ic:make-cipher :aes
                                       :key message-key
                                       :mode :cbc
                                       :padding :pkcs7
                                       :initialization-vector iv)
                       ciphertext
                       :start start
                       :end end)
  (values ciphertext
          start
          (+ start (aref ciphertext (1- end)))))

(defun new-sending-ratchet (client)
  (bt2:with-lock-held ((lock client))
    (bind ((sk (shared-key client))
           (sending-keys (make-25519-private-key))
           ((:values rk cks)
            (kdf-rk sk (exchange-25519-key sending-keys
                                           (other-client-public-key client)))))
      (setf (ratchet client) (make 'ratchet
                                   :root-key rk
                                   :chain-key-send cks
                                   :number-of-messages-in-previous-sending-chain (a:if-let ((old-ratchet (ratchet client)))
                                                                                   (number-of-sent-messages old-ratchet)
                                                                                   0)
                                   :sending-keys sending-keys)))))

(defun exchange-keys (this-client other-client)
  (if (vector< (~> this-client long-term-identity-key ic:curve25519-key-y)
               (~> other-client long-term-identity-key ic:curve25519-key-y))
      (let* ((dh1 (exchange-25519-key (~> this-client long-term-identity-key)
                                      (~> other-client ephemeral-key-1 get-public-key)))
             (dh2 (exchange-25519-key (~> this-client ephemeral-key-2)
                                      (~> other-client long-term-identity-key get-public-key)))
             (dh3 (exchange-25519-key (~> this-client ephemeral-key-3)
                                      (~> other-client long-term-identity-key get-public-key)))
             (dh4 (exchange-25519-key (~> this-client ephemeral-key-4)
                                      (~> other-client long-term-identity-key get-public-key))))
        (setf (slot-value this-client '%shared-key) (concatenate '(simple-array (unsigned-byte 8) (*)) dh1 dh2 dh3 dh4)
              (slot-value this-client '%other-client-public-key) (~> other-client long-term-identity-key get-public-key))
        (new-sending-ratchet this-client))
      (let* ((dh1 (exchange-25519-key (~> this-client ephemeral-key-1)
                                      (~> other-client long-term-identity-key get-public-key)))
             (dh2 (exchange-25519-key (~> this-client long-term-identity-key)
                                      (~> other-client ephemeral-key-2 get-public-key)))
             (dh3 (exchange-25519-key (~> this-client long-term-identity-key)
                                      (~> other-client ephemeral-key-3 get-public-key)))
             (dh4 (exchange-25519-key (~> this-client long-term-identity-key)
                                      (~> other-client ephemeral-key-4 get-public-key))))
        (setf (slot-value this-client '%shared-key) (concatenate '(simple-array (unsigned-byte 8) (*)) dh1 dh2 dh3 dh4)
              (slot-value this-client '%other-client-public-key) (~> other-client long-term-identity-key get-public-key)
              (ratchet this-client) (make 'ratchet
                                          :root-key (slot-value this-client '%shared-key)
                                          :sending-keys (~> this-client long-term-identity-key)))))
  nil)

(defun encrypt* (this-client
                 message
                 start
                 end)
  (bind ((ratchet (ratchet this-client))
         ((:values chain-key message-key initialization-vector) (kdf-ck ratchet (cks ratchet))))
    (setf #1=(number-of-sent-messages ratchet) (mod (1+ #1#) most-positive-fixnum))
    (setf (cks ratchet) chain-key)
    (ic:encrypt-in-place (ic:make-cipher :aes
                                         :key message-key
                                         :mode :cbc
                                         :padding :pkcs7
                                         :initialization-vector initialization-vector)
                         message
                         :start start
                         :end end)
    message))

(defun decrypt* (this-client
                 ciphertext
                 start
                 end)
  (bind ((ratchet (ratchet this-client))
         ((:values chain-key message-key iv) (kdf-ck ratchet (ckr ratchet)))
         ((:values result start end) (decrypt-imlementation message-key iv ciphertext start end)))
    (setf (ckr ratchet) chain-key
          #1=(number-of-received-messages ratchet) (mod (1+ #1#) most-positive-fixnum))
    (values result start end)))

(defun dh-ratchet (this-client
                   public-key
                   number-of-messages-in-previous-sending-chain)
  (let ((ratchet (ratchet this-client)))
    (shiftf (number-of-messages-in-previous-sending-chain ratchet)
            (number-of-sent-messages ratchet)
            0)
    (setf (number-of-received-messages ratchet) 0)
    (bind (((:values rk ckr)
            (kdf-rk (rk ratchet)
                    (exchange-25519-key (~> ratchet sending-keys)
                                        public-key))))
      (setf (received-key ratchet) public-key
            (root-key ratchet) rk
            (ckr ratchet) ckr
            (sending-keys ratchet) (make-25519-private-key)))
    (bind (((:values rk cks)
            (kdf-rk (rk ratchet)
                    (exchange-25519-key (~> ratchet sending-keys)
                                        (received-key ratchet)))))
      (setf (root-key ratchet) rk
            (cks ratchet) cks)))
  nil)

(defun encrypt (double-ratchet
                message)
  (bt2:with-lock-held ((lock double-ratchet))
    (encrypt* double-ratchet
              message
              0
              (length message))
    (make-message (message-class double-ratchet)
                  :sending-key (~> double-ratchet
                                   ratchet
                                   sending-keys
                                   get-public-key)
                  :content message
                  :number (~> double-ratchet
                              ratchet
                              number-of-sent-messages)
                  :message-count-in-previous-sending-chain (~> double-ratchet
                                                               ratchet
                                                               number-of-messages-in-previous-sending-chain))))

(defun can-encrypt-p (object)
  (~> object ratchet cks null not))

(defun try-skipped-messages (double-ratchet message)
  (bind (((:values ciphertext start end) (message-content message))
         ((:values message-key.iv found) (~> double-ratchet
                                             skipped-messages
                                             (skipped-message (message-sending-key message)
                                                              (message-number message)))))

    (if found
        (bind (((message-key . iv) message-key.iv))
          (~> double-ratchet skipped-messages
              (remove-skipped-message (message-sending-key message) (message-number message)))
          (decrypt-imlementation message-key iv ciphertext start end))
        nil)))

(defun skip-message (double-ratchet until)
  (bind (((:accessors (number-of-received-messages number-of-received-messages)
                      (constant constant)
                      (received-key received-key)
                      (ckr ckr))
          (~> double-ratchet ratchet))
         (ratchet (~> double-ratchet ratchet))
         (skipped (~> double-ratchet skipped-messages)))
    (iterate
      (while (< (1+ number-of-received-messages) until))
      (for (values chain-key message-key iv) = (kdf-ck ratchet ckr))
      (setf number-of-received-messages (mod (1+ number-of-received-messages) most-positive-fixnum)
            (skipped-message skipped received-key number-of-received-messages) (cons message-key iv)
            ckr chain-key))))

(defun decrypt (double-ratchet message)
  (bt2:with-lock-held ((lock double-ratchet))
    (bind (((:values vector start end) (try-skipped-messages double-ratchet message)))
      (if vector
          (values vector start end)
          (progn
            (when (or (~> double-ratchet ratchet ckr null)
                      (not (serapeum:vector= (~> message message-sending-key ironclad:curve25519-key-y)
                                             (~> double-ratchet ratchet received-key ironclad:curve25519-key-y))))
              (skip-message double-ratchet (message-count-in-previous-sending-chain message))
              (dh-ratchet double-ratchet
                          (~> message message-sending-key)
                          (message-number message)))
            (skip-message double-ratchet (message-number message))
            (bind (((:values ciphertext start end) (message-content message)))
              (decrypt* double-ratchet
                        ciphertext start end)))))))
