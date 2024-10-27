(asdf:defsystem #:cl-double-ratchet
  :name "cl-double-ratchet"
  :depends-on (#:alexandria
               #:iterate
               #:serapeum
               #:ironclad
               #:metabang-bind
               #:bordeaux-threads
               #:cl-data-structures)
  :serial T
  :pathname "source"
  :components ((:file "package")
               (:file "generics")
               (:file "utils")
               (:file "types")
               (:file "functions")
               (:file "methods")))
