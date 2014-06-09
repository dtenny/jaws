(ns jaws.native_test
  (:require [clojure.test :refer :all]
            [clojure.java.io :refer :all :exclude [copy]]
            [jdt.easyfs :refer :all]
            [jdt.core :refer :all]
            [jaws.native :refer :all]))

;;
;; WARNING: This module will fail if you have stale credentials which are no longer value,
;; it fairly randomly picks up any old credentials laying around in ~/<foo>.aws.cred
;; If will also fail if you have no valid credentials.
;;

;; This isn't going to work for you unless you have some ~/<name>.aws.cred file
;; and ability to execute describe-instances on the account with the credentials.
(deftest test-jdt-cred-files
  (clear-creds)
  (is (= (count @cred-map) 0))
  (add-jdt-cred-files)
  (is (> (count @cred-map) 0))
  (use-cred (first (keys @cred-map)))
  (is (if-let [entry (current-cred-map-entry)]
        (val entry)))
  (describe-instances))

(deftest test-files-as-handles
  (clear-creds)
  (is (= (count @cred-map) 0))
  (is (not (current-cred-map-entry)))
  (let [paths (children "~" {:glob "*.aws.cred"})]
    (add-cred-files paths nil)
    (use-cred (to-file (first paths))))
  (is (current-cred-map-entry)))

(deftest test-quoted-cred-file
  (clear-creds)
  (let [access-key "AKIAIRXXXX7PY3YYYYDQ"
        key-secret "V23fPGoyxtyKh4f6XXXXktUW4DsSYYYYXS9w9kIX"]
    (with-temporary-file [file]
      (with-open [writer (writer file)]
        (printlines-to writer [(str "AWSAccessKeyId=" "\"" access-key "\"")
                               (str "AWSSecretKey=" "'" key-secret "'")]))
      (let [handle (add-cred-file file nil)]
        (use-cred handle)
        (is (= handle file)))
      (let [[_ cred-info] (current-cred-map-entry)]
        (is (= access-key (:access-key cred-info)))
        (is (= key-secret (:key-secret cred-info)))))))

(deftest test-invalid-cred-file
  (clear-creds)
  (is (thrown-with-msg? Exception #"Pattern.*didn't match.*"
               (with-temporary-file [file]
                 (spit file "abcdef\nghi\n")
                 (add-cred-file file :foo)
                 (use-cred :foo))))
  (is (= (count @cred-map) 0))
  (is (thrown? Exception 
               (with-temporary-file [file]
                 (spit file "\n\nfoo\nbar\nbaz\nfoo\n\n")
                 (add-cred-file file :foo)
                 (use-cred :foo))))
  (is (= (count @cred-map) 0)))
