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


(defun make-25519-public-key (y)
  (ic:make-public-key :curve25519 :y y))

(defun make-25519-private-key (&optional (x (ic:random-data 32)))
  (ic:make-private-key :curve25519 :x x))

(defun exchange-25519-key (private-key public-key)
  (ic:diffie-hellman private-key public-key))

(defun padding-bytes-count (length)
  (- 16 (mod length 16)))

(defun make-padded-vector-for-length (length &key initial-contents)
  (let* ((padding-bytes-count (padding-bytes-count length))
         (result (make-array (+ length padding-bytes-count)
                             :element-type '(unsigned-byte 8)
                             :initial-element padding-bytes-count)))
    (replace result initial-contents)
    result))

(defun padded-vector-size (vector &optional (start 0) (end (length vector)))
  (check-type vector (simple-array (unsigned-byte 8) (*)))
  (if (= start end)
      0
      (- end start (aref vector (1- end)))))

(defun make-padded-vector (vector &optional (start 0) (end (length vector)))
  (check-type vector (simple-array (unsigned-byte 8) (*)))
  (make-padded-vector-for-length (- end start)))

(defun pkcs7-pad (vector &optional (start 0) (end (length vector)))
  (declare (type (simple-array (unsigned-byte 8) (*)) vector))
  (lret ((result (make-padded-vector vector)))
    (replace result vector :start2 start :end2 end)))

(defun pkcs7-unpad (vector &optional (start 0) (end (length vector)))
  (check-type vector (simple-array (unsigned-byte 8) (*)))
  (subseq vector start (padded-vector-size vector start end)))

(defun get-public-key (key)
  (if (typep key 'ironclad:curve25519-public-key)
      key
      (let* ((y (ic:curve25519-key-y key))
             (public (ic:make-public-key :curve25519 :y y)))
        public)))

(defun key-ordering (a b)
  (< a b))

(defun make-skipped-messages ()
  (serapeum:box (list)))

(defun skipped-message (skipped-messages chain-key message-number)
  (alexandria:if-let ((hash-table (assoc (ironclad:curve25519-key-y chain-key)
                                         (serapeum:unbox skipped-messages)
                                         :test #'serapeum:vector=)))
    (gethash message-number (cdr hash-table))
    (values nil nil)))

(defun (setf skipped-message) (new-value skipped-messages chain-key message-number &aux (vector (ironclad:curve25519-key-y chain-key)))
  (alexandria:if-let ((hash-table (assoc vector
                                         (serapeum:unbox skipped-messages)
                                         :test #'serapeum:vector=)))
    (setf (gethash message-number (cdr hash-table)) new-value)
    (push (cons vector
                (lret ((result (make-hash-table)))
                  (setf (gethash message-number result) new-value)))
          (serapeum:unbox skipped-messages)))
  new-value)

(defun remove-skipped-message (skipped-messages chain-key message-number &aux (vector (ironclad:curve25519-key-y chain-key)))
  (alexandria:when-let ((hash-table (assoc vector
                                           (serapeum:unbox skipped-messages)
                                           :test #'serapeum:vector=)))
    (remhash message-number (cdr hash-table))
    (when (~> hash-table cdr hash-table-count zerop)
      (setf #1=(serapeum:unbox skipped-messages)
            (delete-if (alexandria:curry #'serapeum:vector= vector)
                       #1# :key #'car))))
  nil)
