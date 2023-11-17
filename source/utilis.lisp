(cl:in-package #:double-ratchet)


(defun make-25519-public-key (private)
  (ironclad:make-public-key :curve25519 :y private))

(defun make-25519-private-key ()
  (ironclad:make-private-key :curve25519 :x (ironclad:random-data 32)))

(defun make-25519-keys ()
  (let* ((x (ironclad:random-data 32))
         (private (ironclad:make-private-key :curve25519 :x x))
         (y (ironclad:curve25519-key-y private))
         (public (ironclad:make-public-key :curve25519 :y y)))
    (make-instance 'key-pair :public public :private private)))

(defun exchange-25519-key (private-key public-key)
  (ironclad:diffie-hellman private-key public-key))

(defun chain-key-length (chain)
  (array-dimension (key chain) 0))

(defun make-chain (key)
  (make-instance 'chain :key key))

(defun make-symmetric-ratchet (key)
  (make-instance 'symmetric-ratchet :chain (make-chain key)))

(defun make-diffie-hellman-ratchet (shared-key &optional (root-ratchet (make-symmetric-ratchet shared-key)))
  (let* ((recv-chain (make-symmetric-ratchet (next-key root-ratchet)))
         (send-ratchet (make-symmetric-ratchet (next-key root-ratchet))))
    (make-instance 'diffie-hellman-ratchet
                   :root-ratchet root-ratchet
                   :receiving-ratchet recv-chain
                   :sending-ratchet send-ratchet)))
