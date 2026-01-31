;;; tests/test-helper.el --- Shared testing utilities -*- lexical-binding: t -*-

(require 'ert)
(require 'cl-lib)
(require 'json)

(defvar auth-source-sops-test-dir
  (file-name-directory (or load-file-name buffer-file-name)))

;; Load the library
(require 'auth-source-sops (expand-file-name "../auth-source-sops.el" auth-source-sops-test-dir))

;; Setup mock-yaml for unit tests
(require 'mock-yaml (expand-file-name "mock-yaml.el" auth-source-sops-test-dir))

(defmacro auth-source-sops-test-with-temp-file (var-name suffix &rest body)
  "Create a temp file, assign path to VAR-NAME, run BODY, and delete file."
  (declare (indent 2))
  `(let ((,var-name (make-temp-file "auth-sops-test" nil ,suffix)))
     (unwind-protect
         (progn ,@body)
       (when (file-exists-p ,var-name)
         (delete-file ,var-name)))))

(defmacro auth-source-sops-test-with-mock-environment (&rest body)
  "Set up a isolated environment for auth-source-sops tests."
  (declare (indent 0))
  `(let ((temp-file (make-temp-file "auth-sops-unit-test" nil ".yaml")))
     (cl-letf (((symbol-function 'auth-source-sops-decrypt) (lambda () "mocked-content"))
               ((symbol-function 'yaml-parse-string) #'mock-yaml-parse-string))
       (unwind-protect
           (let ((auth-source-sops-file temp-file)
                 (auth-source-sops-age-key-source 'environment)
                 (auth-source-sops-search-method :full)
                 (auth-sources '(sops))
                 (auth-source-do-cache nil)
                 (auth-source-sops--raw-cache nil)
                 (auth-source-sops--derived-age-key nil)
                 (process-environment (copy-sequence process-environment)))
             (auth-source-sops-enable)
             ,@body)
         (when (file-exists-p temp-file) (delete-file temp-file))))))


(defun auth-source-sops-test-get-age-key ()
  "Get the test age key from the environment or file."
  (let ((key-file (expand-file-name "age" auth-source-sops-test-dir)))
    (with-temp-buffer
      (insert-file-contents key-file)
      (string-trim (buffer-string)))))

(defun auth-source-sops-test-get-age-recipient ()
  "Get the standard test age recipient."
  "age1yqvertkprae737vpmdgd82nnqkg2uh6xdlp9pv4eqchqa92yjpuskfevcv")

(provide 'test-helper)
