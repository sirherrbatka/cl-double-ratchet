
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


(defmacro with-ratchet-undo ((client) &body body)
  (a:once-only (client)
    (a:with-gensyms (!number-of-messages-in-previous-sending-chain
                     !number-of-sent-messages
                     !number-of-received-messages
                     !received-key
                     !root-key
                     !ckr
                     !sending-keys
                     !ratchet
                     !cks)
      `(let* ((,!ratchet (ratchet ,client))
              (,!number-of-messages-in-previous-sending-chain (number-of-messages-in-previous-sending-chain ,!ratchet))
              (,!number-of-sent-messages (number-of-sent-messages ,!ratchet))
              (,!number-of-received-messages (number-of-received-messages ,!ratchet))
              (,!received-key (received-key ,!ratchet))
              (,!root-key (root-key ,!ratchet))
              (,!ckr (ckr ,!ratchet))
              (,!sending-keys (sending-keys ,!ratchet))
              (,!cks (cks ,!ratchet)))
         (flet ((undo ()
                  (setf (number-of-messages-in-previous-sending-chain ,!ratchet) ,!number-of-messages-in-previous-sending-chain
                        (number-of-sent-messages ,!ratchet) ,!number-of-sent-messages
                        (number-of-received-messages ,!ratchet) ,!number-of-received-messages
                        (received-key ,!ratchet) ,!received-key
                        (root-key ,!ratchet) ,!root-key
                        (ckr ,!ratchet) ,!ckr
                        (sending-keys ,!ratchet) ,!sending-keys
                        (cks ,!ratchet) ,!cks)))
           (declare (ignorable (function undo)))
           ,@body)))))
