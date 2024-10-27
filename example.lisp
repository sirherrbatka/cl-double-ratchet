(ql:quickload :cl-double-ratchet)

(cl:in-package #:double-ratchet)


(defparameter *client-a* (make-local-client (make-25519-private-key)))
(defparameter *client-b* (make-local-client (make-25519-private-key)))

(exchange-keys* *client-a* *client-b*)
(exchange-keys* *client-b* *client-a*)

(unless (can-encrypt-p *client-a*)
  (rotatef *client-a* *client-b*))

(defparameter *double-ratchet-1*
  (make-instance 'double-ratchet
                  :local-client *client-a*
                  :remote-client *client-b*))

(defparameter *double-ratchet-2*
  (make-instance 'double-ratchet
                  :remote-client *client-a*
                  :local-client *client-b*))

(can-encrypt-p *double-ratchet-1*)

(defparameter *encrypted-1* (encrypt *double-ratchet-1*
                                     (make-padded-vector-for-length 20 :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20))))

(defparameter *decrypted-1* (decrypt *double-ratchet-2* *encrypted-1*))

(defparameter *encrypted-2* (encrypt *double-ratchet-1*
                                     (make-padded-vector-for-length 20 :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20))))

(defparameter *decrypted-2* (decrypt *double-ratchet-2* *encrypted-2*))

(defparameter *encrypted-3* (encrypt *double-ratchet-2*
                                     (make-padded-vector-for-length 20 :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20))))

(defparameter *decrypted-3* (decrypt *double-ratchet-1* *encrypted-3*))
