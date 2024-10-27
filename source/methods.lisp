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


(defmethod exchange-keys* ((client-a local-client)
                           (client-b client))
  (if (vector< (~> client-a long-term-identity-key ic:curve25519-key-y)
               (~> client-b long-term-identity-key ic:curve25519-key-y))
      (let* ((dh1 (exchange-25519-key (~> client-a long-term-identity-key)
                                      (~> client-b ephemeral-key-1 get-public-key)))
             (dh2 (exchange-25519-key (~> client-a ephemeral-key-2)
                                      (~> client-b long-term-identity-key get-public-key)))
             (dh3 (exchange-25519-key (~> client-a ephemeral-key-3)
                                      (~> client-b long-term-identity-key get-public-key)))
             (dh4 (exchange-25519-key (~> client-a ephemeral-key-4)
                                      (~> client-b long-term-identity-key get-public-key))))
        (setf (slot-value client-a '%shared-key) (concatenate '(simple-array (unsigned-byte 8) (*)) dh1 dh2 dh3 dh4)
              (slot-value client-b '%shared-key) (slot-value client-a '%shared-key)
              (ratchet client-a) (bind ((sk (slot-value client-a '%shared-key)) ; this is remote-client RK
                                        ((:values rk cks)
                                         (kdf-rk sk (exchange-25519-key (~> client-a ephemeral-key-1)
                                                                        (~> client-b ephemeral-key-1 get-public-key)))))
                                   (make 'ratchet
                                         :root-key rk
                                         :chain-key-send cks
                                         :sending-keys (ephemeral-key-1 client-a)
                                         :received-key (ephemeral-key-1 client-b)
                                         :chain-key-receive nil))))
      (let* ((dh1 (exchange-25519-key (~> client-a ephemeral-key-1)
                                      (~> client-b long-term-identity-key get-public-key)))
             (dh2 (exchange-25519-key (~> client-a long-term-identity-key)
                                      (~> client-b ephemeral-key-2 get-public-key)))
             (dh3 (exchange-25519-key (~> client-a long-term-identity-key)
                                      (~> client-b ephemeral-key-3 get-public-key)))
             (dh4 (exchange-25519-key (~> client-a long-term-identity-key)
                                      (~> client-b ephemeral-key-4 get-public-key))))
        (setf (slot-value client-a '%shared-key) (concatenate '(simple-array (unsigned-byte 8) (*)) dh1 dh2 dh3 dh4)
              (slot-value client-b '%shared-key) (slot-value client-a '%shared-key)
              (ratchet client-a) (make 'ratchet
                                       :root-key (slot-value client-a '%shared-key)
                                       :sending-keys (~> client-a ephemeral-key-1)))))
  nil)

(defmethod encrypt* ((this-client client)
                     (other-client client)
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

(defmethod decrypt* ((this-client client)
                     (other-client client)
                     ciphertext
                     start
                     end)
  (bind ((ratchet (ratchet this-client))
         ((:values chain-key message-key iv) (kdf-ck ratchet (ckr ratchet)))
         ((:values result start end) (decrypt-imlementation message-key iv ciphertext start end)))
    (setf (ckr ratchet) chain-key
          #1=(number-of-received-messages ratchet) (mod (1+ #1#) most-positive-fixnum))
    (values result start end)))

(defmethod dh-ratchet ((this-client client)
                       public-key
                       number-of-sent-messages
                       number-of-messages-in-previous-sending-chain)
  (let ((ratchet (ratchet this-client)))
    (when (and (not (null (received-key ratchet)))
               (vector= (ironclad:curve25519-key-y (received-key ratchet))
                        (ironclad:curve25519-key-y public-key)))
      (return-from dh-ratchet nil))
    (shiftf (number-of-messages-in-previous-sending-chain ratchet)
            (number-of-sent-messages ratchet)
            0)
    (bind (((:values rk ckr)
            (kdf-rk (rk ratchet)
                    (exchange-25519-key (~> ratchet sending-keys)
                                        public-key))))
      (setf (receive-key ratchet) public-key
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

(defmethod encrypt ((double-ratchet double-ratchet)
                    message)
  (bt2:with-lock-held ((lock double-ratchet))
    (encrypt* (local-client double-ratchet)
              (remote-client double-ratchet)
              message
              0
              (length message))
    (make-message (message-class double-ratchet)
                  :sending-key (~> double-ratchet
                                   local-client
                                   ratchet
                                   sending-keys
                                   get-public-key)
                  :content message
                  :number (~> double-ratchet
                              local-client
                              ratchet
                              number-of-sent-messages)
                  :message-count-in-previous-sending-chain (~> double-ratchet
                                                               local-client
                                                               ratchet
                                                               number-of-messages-in-previous-sending-chain))))

(defmethod decrypt ((double-ratchet double-ratchet)
                    message)
  (bt2:with-lock-held ((lock double-ratchet))
    (unless (~> double-ratchet local-client ratchet ckr)
      (dh-ratchet (local-client double-ratchet)
                  (~> message message-sending-key)
                  (message-number message)
                  (message-count-in-previous-sending-chain message)))
    (bind (((:values vector start end) (try-skipped-messages double-ratchet message)))
      (if vector
          (values vector start end)
          (progn
            (skip-message (message-number message))
            (bind (((:values ciphertext start end) (message-content message)))
              (decrypt* (local-client double-ratchet)
                        (remote-client double-ratchet)
                        ciphertext start end)))))))

(defmethod long-term-identity-remote-key ((object double-ratchet))
  (~> object remote-client long-term-identity-key get-public-key))

(defmethod can-encrypt-p ((object double-ratchet))
  (~> object local-client can-encrypt-p))

(defmethod can-encrypt-p ((object client))
  (~> object ratchet cks null not))

(defmethod message-content ((message message))
  (let ((result (read-message-content message)))
    (values result 0 (length result))))

(defmethod try-skipped-messages ((double-ratchet double-ratchet) message)
  (bind (((:values ciphertext start end) (message-content message))
         (number (message-number message))
         (key (~> double-ratchet local-client ratchet received-key))
         (index (cons number key))
         ((:values message-key.iv found) (~> double-ratchet
                                             local-client
                                             skipped-messages
                                             (cl-ds:at index))))
    (if found
        (bind (((message-key . iv) message-key.iv))
          (~> double-ratchet local-client skipped-messages (cl-ds:erase! index))
          (decrypt-imlementation message-key iv ciphertext start end))
        nil)))

(defmethod skip-message ((double-ratchet double-ratchet) until)
  (bind (((:accessors (number-of-received-messages number-of-received-messages)
                      (constant constant)
                      (ckr ckr))
          (~> double-ratchet local-client ratchet))
         (ratchet (~> double-ratchet local-client ratchet))
         (skipped (~> double-ratchet local-client skipped-messages)))
    (iterate
      (while (< number-of-received-messages until))
      (for (values chain-key message-key iv) = (kdf-ck ratchet ckr))
      (setf number-of-received-messages (mod (1+ number-of-received-messages) most-positive-fixnum))
      (setf ckr chain-key)
      (setf (cl-ds:at skipped (cons number-of-received-messages chain-key)) (cons message-key iv)))))
