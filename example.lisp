(ql:quickload :cl-double-ratchet)

(cl:in-package #:double-ratchet)


(defparameter *client-a* (make-client (make-25519-private-key)))
(defparameter *client-b* (make-client (make-25519-private-key)))

(exchange-keys* *client-a* *client-b*)
(exchange-keys* *client-b* *client-a*)

(unless (can-encrypt-p *client-a*)
  (rotatef *client-a* *client-b*))

(defparameter *encrypted-1* (encrypt *client-a*
                                     (make-padded-vector-for-length 20 :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20))))

(defparameter *decrypted-1* (decrypt *client-b* *encrypted-1*))

(defparameter *encrypted-2* (encrypt *client-a*
                                     (make-padded-vector-for-length 20 :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20))))

(defparameter *encrypted-3* (encrypt *client-b*
                                     (make-padded-vector-for-length 20 :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20))))

(defparameter *encrypted-4* (encrypt *client-b*
                                     (make-padded-vector-for-length 20 :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20))))

(defparameter *decrypted-4* (decrypt *client-a* *encrypted-4*))

(defparameter *decrypted-3* (decrypt *client-a* *encrypted-3*))

(defparameter *decrypted-2* (decrypt *client-b* *encrypted-2*))
