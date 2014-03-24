(ns jaws.core
  (:use [jdt core cl shell easyfs])
  (:use [clojure.java.io])
  (:use [clojure.pprint :only [cl-format]])
  (:use [clojure.tools.logging :exclude [trace]])
  (:use clojure.set)
  (:require [amazonica.aws.ec2 :as ec2])
  (:require [amazonica.aws.identitymanagement :as iam])
  (:use [amazonica.core :only [defcredential with-credential]])
  (:import java.io.File))

;; If you're trying to play with this stuff in user namespace
#_ 
(do
  (require '[jaws.core :as jaws])
  (require '[amazonica.aws.ec2 :as ec2])
  (require '[amazonica.aws.identitymanagement :as iam]))

;; Parameter name legend:
;; 'm' == map, 'e' == map-entry, 'v' == vec, 's' = seq

(defn- ensure-one-line "Fail we matched other than one line" [matched-lines key]
  (when (> (count matched-lines) 1)
    (throw (Exception. (cl-format nil "Matched too many ~s lines:~%~{  ~s~^~%~}~%"
                                  key matched-lines))))
  (when (< (count matched-lines) 1)
    (throw (Exception. (str "Didn't match any lines for" key)))))

(def- ACCESS_KEY_PATTERN "Access key pattern for re-find or re-match"
  #"(?i)^.*access.*=\s*(\S{20})\s*$")
(def- SECRET_KEY_PATTERN "Secret key pattern for re-find or re-match"
  #"(?i)^.*secret.*=\s*(\S{40})\s*$")

(defn parse-cred "Return [access-key secret-key] or nil if not found in file"
  [f]
  (let [matchmap (select-matching-strings (readlines (as-file f))
                   {:key ACCESS_KEY_PATTERN :secret SECRET_KEY_PATTERN} re-find)
        keylines (:key matchmap)
        secretlines (:secret matchmap)]
    (ensure-one-line keylines :key)
    (ensure-one-line secretlines :secret)
    [(second (re-find ACCESS_KEY_PATTERN (first keylines)))
     (second (re-find SECRET_KEY_PATTERN (first secretlines)))]))

(def cred-paths "Files we consult for credentials"
  (children "~" {:glob "*.aws.cred"}))

(def cred-map
  "Map keyed by partial cred file identifier, valued by [key secret path] vectors."
  (atom 
   (into {}
         (map (fn [path]
                (let [keyname (keyword (second (re-find #"([^.]+).aws.cred"
                                                        (str (.getFileName path)))))
                      key-secret-vec (parse-cred path)]
                  (unless key-secret-vec
                          (warn "Unable to find credentials in " path))
                  {keyname (conj key-secret-vec path)}))
              cred-paths))))

(defn third [coll] (nth coll 2))
(defn cred-map-entry-access-key [map-entry] (first (val map-entry)))
(defn cred-map-entry-secret [map-entry] (second (val map-entry)))
(defn cred-map-entry-file-path [map-entry] (third (val map-entry)))
(defn get-cred-map-entry-for-access-key
  "Return the map entry access key (vs. cred-map key), or nil if there isn't one."
  [access-key]
  (first (filter #(= (cred-map-entry-access-key %) access-key) @cred-map)))

(defn prompt-for-credentials
  "Prompt user for keyword into cred-map for credential set to use.
  Return the (validated) keyword."
  []
  (println "The following credential files are known:")
  (doseq [entry (seq @cred-map)]
    (cl-format true "  ~s~,20tmaps to ~a~%"
               (key entry) (str (third (val entry)))))
  (loop [answer (read-string
                 (prompt "Which credentials would you like to use? (specify keyword)"))]
    (if-let [creds (answer @cred-map)]
      answer
      (recur (do (println "Invalid credential keyword" answer)
                 (read-string (prompt "Which credential keyword?")))))))
      
;; We wrap amazonica's defcedential so we can query the credentials in use
;; (which amazonica hides in a private atom), and so we can see the creds represented
;; as a keyword in cred-map isntead of something less intuitive.
(defonce
  ^{:private true :doc
    "Key in cred-map whose credentials we're using.
    A nil key means we're using whatever is in the calling process environment."}
  cred-key (atom nil))

(defn current-cred-map-entry
  "Return the map entry in cred-map indicating current credentials in use
   or nil if there aren't any except those imposed by the process' calling environment
  (Which you can get with environment-creds)."
  []
  (if-let [key (deref cred-key)]
    (find @cred-map key)))

;;DefaultAWSCredentialsProviderChain 	
;;AWS credentials provider chain that looks for credentials in this order: Environment Variables - AWS_ACCESS_KEY_ID and AWS_SECRET_KEY Java System Properties - aws.accessKeyId and aws.secretKey Instance profile credentials delivered through the Amazon EC2 metadata service
;;EnvironmentVariableCredentialsProvider 	
;;AWSCredentialsProvider implementation that provides credentials by looking at the: AWS_ACCESS_KEY_ID (or AWS_ACCESS_KEY) and AWS_SECRET_KEY (or AWS_SECRET_ACCESS_KEY) environment variables.
(defn environment-creds []
  "Return information on credentials in the calling process environment that could
  be used by this module if not superseded by use of 'defcred' or related amazonica behavior."
  ;; I'm using here what the EC2 CLI uses.
  (let [key (System/getenv "AWS_ACCESS_KEY")
        secret (System/getenv "AWS_SECRET_KEY")]
    (if (and key secret)
      {:*env* [key secret nil]})))

(defn defcred
  "Specify in-process amazon credentials which will override any active in the
  jaws process environment.  This is a one way trip, amazonica doesn't currently
  allow us to revert its own defcredential settings to 'none'.
  The key specified must be a key in the 'cred-map'.
  (defcred (prompt-for-credentials)) may be useful."
  [key]
  (if-let [creds (key @cred-map)]
    (do (apply defcredential (take 2 creds))
        (reset! cred-key key))
    (throw (Exception. (str "Invalid cred-map key: " key)))))
  
(defn choose-creds
  "Interactive selectiobn and activataion of credentials for future AWS interaction."
  []
  (defcred (prompt-for-credentials))
  (println "Current creds:" (current-cred-map-entry)))

(if-not @cred-key
  (choose-creds))

(defn update-cred
  "Given a key value pair as would be present in 'cred-map',
  update or add the key (with new value) in the cred-map."
  [credkey credvalue]
  (when-let [old-creds (credkey @cred-map)]
    (println "Replacing" credkey "credentials")
    (println "  Old:" old-creds)
    (println "  New:" credvalue)
    (do (reset! cred-map (assoc @cred-map credkey credvalue))
        (when (= credkey @cred-key)
          (println "Using new AWS credentials")
          (apply defcredential (take 2 credvalue))))))


;;;
;;; EC2 instance queries
;;;

;; Would really like a tool that analizes unique map keys maybe types
;; for nested map/seq hierarchies.  To help me know what to know what keys are available
;; at each level.
(comment
  (defonce sample (ec2/describe-instances)) ; map with one key, :reservations
  (def reservations (:reservations sample)) ; vector of reservations
  (def instances-grouped-by-reservation
    (map :instances reservations)) ; seq of seqs of instances in all reservations
  (def instances (flatten instances-grouped-by-reservation)) ; seq of maps with instance data
  (def instance-ids (map :instance-id instances))
  (def instance-submaps (map #(select-keys % [:instance-id :instance-type]) instances))

  ;; Same as... (minus final keys)
  #_
  (->> sample                     ;map with one key, :reservations
       :reservations              ;vector of reservation maps
       (map :instances)           ;sequence of instances from all reservations
       flatten
       (map #(select-keys % [:instance-id :instance-type :public-ip-address])))
  )

(defn print-instance-maps
  "Print a sequence of maps containing per-instance data in some human friendly way.  Returns nil."
  [s]
  ;; Get all keys in maps, assign priorities to the order in which some keys are presented
  ;; print keys of maps in order with formatted field widths
  (let [all-keys (into #{} (flatten (map keys s)))
        ordered-keys [:instance-id :image-id :vpc-id :public-dns-name :state]
        ordered-keys-set (into #{} ordered-keys)
        ordered-keys (into ordered-keys (clojure.set/difference all-keys ordered-keys-set))
        min-field-widths (mapv #(count (str %)) ordered-keys)
        ordered-value-lists (map (fn [m] (map (fn [k] (k m)) ordered-keys)) s)
        ordered-value-length-lists (map (fn [l] (map (fn [v] (count (str v))) l)) ordered-value-lists)
        max-field-widths (reduce (fn [vals1 vals2] (map max vals1 vals2))
                                 min-field-widths ordered-value-length-lists)
        n-fields (count ordered-keys)]
    ;;(println "ordered-value-lists(1):" (first ordered-value-lists))
    ;;(println "ordered-value-length-lists(1):" (first ordered-value-length-lists))
    ;;(println "max-field-widths:" max-field-widths)
    (doseq [[w k] (for [x (range n-fields)] [(nth max-field-widths x) (nth ordered-keys x)])]
      (clojure.pprint/cl-format true "~vs " w k))
    (println)
    (doseq [l ordered-value-lists]
      (doseq [[w v] (for [x (range n-fields)] [(nth max-field-widths x) (nth l x)])]
        (clojure.pprint/cl-format true "~va " w v))
      (println))
    nil))

(defn list-instances
  "Print instance information to terminal, return sequence of maps, one per instnace, with select
   attribute keys."
  []
  (let [instance-maps 
        (->> (ec2/describe-instances)
             :reservations
             (map :instances)
             flatten
             (map #(select-keys % [:instance-id :vpc-id :image-id :instance-type
                                   :public-dns-name :tags :state]))
             (map #(merge % {:state (get-in % [:state :name])}))
             )]
    (print-instance-maps instance-maps)
    instance-maps))

;;;
;;; IAM
;;;

;;user> (iam/create-access-key :user-name "dtenny")
;;{:access-key {:secret-access-key "xd6ZKV2s1LfPsKGhDxgrXOj2Gqr4lJniQeQOpHrv", :status "Active", :access-key-id "AKIAJQ36WCPC57C5EPIA", :create-date #<DateTime 2014-03-18T14:20:56.799-05:00>, :user-name "dtenny"}}
;;user> (iam/update-access-key :access-key-id "AKIAJQ36WCPC57C5EPIA" :status "Inactive")
;;nil
;;user> (iam/list-access-keys)
;;{:access-key-metadata [{:status "Active", :access-key-id "AKIAJOGACDIRSSXI2YIQ", :create-date #<DateTime 2013-12-06T06:11:06.000-05:00>, :user-name "dtenny"} {:status "Inactive", :access-key-id "AKIAJQ36WCPC57C5EPIA", :create-date #<DateTime 2014-03-18T14:20:56.000-05:00>, :user-name "dtenny"}], :is-truncated false}
;;user> (iam/delete-access-key :access-key-id "AKIAJQ36WCPC57C5EPIA")
;;nil
;;user> (iam/list-access-keys)
;;{:access-key-metadata [{:status "Active", :access-key-id "AKIAJOGACDIRSSXI2YIQ", :create-date #<DateTime 2013-12-06T06:11:06.000-05:00>, :user-name "dtenny"}], :is-truncated false}
;;user> (iam/get-user)
;;{:user {:user-id "AIDAJDCYQGPATRJYSPFHG", :arn "arn:aws:iam::181951604100:user/dtenny", :create-date #<DateTime 2013-12-05T14:38:05.000-05:00>, :user-name "dtenny", :path "/"}}

(defn get-user-name "Get the user-name of an iam user" []
  (get-in (iam/get-user) [:user :user-name]))
(defn get-user-account-number "Get the AWS account number of an iam user (as a string)" []
  (second (re-find #".*::(\d+):" (get-in (iam/get-user) [:user :arn]))))

(defn make-credentials
  "Create a new set of IAM credentials, 
   Create a file with those credentials in AWS_CREDENTIAL_FILE format,
   i.e. the same format parsed by 'parse-cred'.
   Return a vector of [key secret path] information as is held in cred-map containing the resulting information."
  []
  (let [user-data (iam/get-user)
        user-name (get-in user-data [:user :user-name])
        user-account (second (re-find #".*::(\d+):" (get-in user-data [:user :arn])))
        file-name (str "/tmp/aws-" user-name "-" user-account ".cred")
        file (File. file-name)
        access-key-data (iam/create-access-key :user-name (get-user-name))
        key (get-in access-key-data [:access-key :access-key-id])
        secret (get-in access-key-data [:access-key :secret-access-key])]
    (with-open [stream (writer file)]
      (cl-format stream "AWSAccessKeyId=~a~%" key)
      (cl-format stream "AWSSecretKey=~a~%" secret))
    (println "Created new key:" access-key-data "in file" (str file))
    [key secret (.toPath file)]))

(defn- active? [m]
  (= (:status m) "Active"))

(defn rotate-keys
  "Rotate access keys for current credentials (as in (defcred (prompt-for-credentials))).
   Inactive keys will be deleted.
   Active keys will be made inactive.
   A new active key is created, and the credentials files on disk and tables in memory are updated."
  []
  (let [result (iam/list-access-keys)
        keys (:access-key-metadata result)
        active-keys (filter active? keys)
        inactive-keys (filter #(not (active? %)) keys)]
    (assert (not (:is-truncated result)))
    (when (seq inactive-keys)
      (doseq [new-key-state inactive-keys]
        (println "Deleting inactive key:" new-key-state)
        (iam/delete-access-key :access-key-id (:access-key-id new-key-state))))
    (when (seq active-keys)
      ;; First delete active keys we aren't using.
      (doseq [old-key-state active-keys]
        (let [old-access-key (:access-key-id old-key-state)
              e (get-cred-map-entry-for-access-key old-access-key)
              cred-file-path (and e (cred-map-entry-file-path e))]
          (unless cred-file-path
                  (println "Deleting active key because we don't appear to be using it:" old-key-state)
                  (iam/delete-access-key :access-key-id old-access-key))))
      ;; Need new credentials, in use, before we attempt to delete old (but currently in use) credentials
      (let [new-creds (make-credentials) ; [key secret path]
            new-path (third new-creds)
            new-pathstr (str new-path)]
        (doseq [old-key-state active-keys]
          (let [old-access-key (:access-key-id old-key-state)
                e (get-cred-map-entry-for-access-key old-access-key)
                cred-file-path (and e (cred-map-entry-file-path e))]
            (when cred-file-path
              (let [tmp-file (as-file new-pathstr)
                    cred-file (as-file cred-file-path)]
                (println "Updating credential file" (str cred-file-path) "with" new-pathstr)
                (.delete cred-file)
                (copy tmp-file cred-file)
                (.delete tmp-file)
                (update-cred (key e) [(first new-creds) (second new-creds) cred-file-path])
                ;; Not clear how long we need to sleep here, but if we don't sleep
                ;; the new credentials may not yet be valid.
                (Thread/sleep 3000)
                (println "Deactivating:" old-key-state)
                (iam/update-access-key :access-key-id old-access-key :status "Inactive")))))))))


