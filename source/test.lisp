(cl:in-package #:pantalea.cryptography)

(defparameter *client-a* (make-local-client (make-25519-keys)))
(defparameter *client-b* (make-local-client (make-25519-keys)))

(exchange-keys* *client-a* *client-b*)
(exchange-keys* *client-b* *client-a*)

(unless (can-encrypt-p *client-a*)
  (rotatef *client-a* *client-b*))

(defparameter *double-ratchet*
  (make-instance 'double-ratchet
                  :local-client *client-a*
                  :remote-client *client-b*))

(can-encrypt-p *double-ratchet*)

(defparameter *message*
  (make-array 20 :element-type '(unsigned-byte 8) :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20)))

(defparameter *encrypted-1* (encrypt *double-ratchet* *message*))

(defparameter *decrypted-1* (decrypt (make-instance 'double-ratchet
                                                    :remote-client *client-a*
                                                    :local-client *client-b*)
                                   *encrypted-1*))

(defparameter *encrypted-2* (encrypt *double-ratchet*
                                     *message*))

(defparameter *decrypted-2* (decrypt (make-instance 'double-ratchet
                                                    :remote-client *client-a*
                                                    :local-client *client-b*)
                                   *encrypted-2*))
