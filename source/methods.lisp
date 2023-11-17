(cl:in-package #:double-ratchet)


(defmethod forward ((chain chain) bytes &optional (length 32))
  (let* ((chain-key-length (chain-key-length chain))
         (output (ironclad:derive-key (kdf chain)
                                      bytes
                                      (key chain)
                                      (iteration-count chain)
                                      (+ chain-key-length length)))
         (result (subseq output chain-key-length)))
    (setf (key chain) (subseq output 0 chain-key-length))
    (write-steps (1+ (steps chain)) chain )
    result))

(defmethod steps ((ratchet symmetric-ratchet))
  (steps (chain ratchet)))

(defmethod move-ratchet ((ratchet symmetric-ratchet) &optional (bytes (constant ratchet)))
  (forward (chain ratchet) (constant ratchet) 80))

(defmethod next-key ((ratchet symmetric-ratchet) &optional (bytes (constant ratchet)))
  (let ((result (move-ratchet ratchet bytes)))
    (values (subseq result 32 64)
            (subseq result 64))))

(defmethod extended-triple-diffie-hellman ((client-a remote-client)
                                           (client-b local-client))
  (let* ((dh1 (exchange-25519-key (private (signed-pre-key client-a))
                                  (public (long-term-identity-key client-b))))
         (dh2 (exchange-25519-key (private (long-term-identity-key client-a))
                                  (public (ephemeral-key client-b))))
         (dh3 (exchange-25519-key (private (signed-pre-key client-a))
                                  (public (ephemeral-key client-b))))
         (dh4 (exchange-25519-key (private (one-time-pre-keys client-a))
                                  (public (ephemeral-key client-b)))))
    (setf (slot-value client-a '%shared-key)
          (concatenate '(simple-array (unsigned-byte 8) (*))
                       dh1
                       dh2
                       dh3
                       dh4))))

(defmethod extended-triple-diffie-hellman ((client-a local-client)
                                           (client-b remote-client))
  (let* ((dh1 (exchange-25519-key (private (long-term-identity-key client-a))
                                  (public (signed-pre-key client-b))))
         (dh2 (exchange-25519-key (private (ephemeral-key client-a))
                                  (public (long-term-identity-key client-b))))
         (dh3 (exchange-25519-key (private (ephemeral-key client-a))
                                  (public (signed-pre-key client-b))))
         (dh4 (exchange-25519-key (private (ephemeral-key client-a))
                                  (public (one-time-pre-keys client-b)))))
    (setf (slot-value client-a '%shared-key)
          (concatenate '(simple-array (unsigned-byte 8) (*))
                       dh1
                       dh2
                       dh3
                       dh4))))

(defmethod extended-triple-diffie-hellman :after ((client-a client)
                                                  (client-b client))
  (setf (slot-value client-a '%diffie-hellman-ratchet)
        (make-diffie-hellman-ratchet (shared-key client-a))))

(defmethod private-key ((ratchet diffie-hellman-ratchet))
  (private (keys ratchet)))

(defmethod public-key ((ratchet diffie-hellman-ratchet))
  (public (keys ratchet)))

(defmethod encrypt* ((this-client client)
                     (other-client client)
                     message)
  (multiple-value-bind (key iv)
      (~> this-client
          diffie-hellman-ratchet
          sending-ratchet
          next-key)
    (lret ((result (copy-array message)))
      (ironclad:encrypt (ironclad:make-cipher :aes :key key :mode :cbc :initialization-vector iv)
                        message
                        result))))

(defmethod decrypt* ((this-client client)
                     (other-client client)
                     cipher)
  (rotate-ratchet this-client (public (keys other-client)))
  (multiple-value-bind (key iv)
      (~> this-client
          diffie-hellman-ratchet
          receiving-ratchet
          next-key)
    (lret ((result (copy-array cipher)))
      (ironclad:decrypt (ironclad:make-cipher :aes :key key :mode :cbc :initialization-vector iv)
                        cipher
                        result))))

(defmethod rotate-ratchet ((this-client client) public-key)
  (unless (null (keys this-client))
    (let* ((dh-recv (ironclad:diffie-hellman (private (keys this-client)) public-key))
           (shared-recv (~> this-client diffie-hellman-ratchet root-ratchet (next-key dh-recv))))
      (setf (receiving-ratchet (diffie-hellman-ratchet this-client)) (make-symmetric-ratchet shared-recv))))
  (setf (keys this-client) (make-25519-keys))
  (let* ((dh-send (ironclad:diffie-hellman (private (keys this-client)) public-key))
         (shared-send (~> this-client diffie-hellman-ratchet root-ratchet (next-key dh-send))))
    (setf (sending-ratchet (diffie-hellman-ratchet this-client)) (make-symmetric-ratchet shared-send))))
