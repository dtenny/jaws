(ns jaws.native
  (:use clojure.repl)
  (:use clojure.set)
  (:use [jdt core cl shell easyfs])
  (:use [clojure.java.io])
  (:use [clojure.pprint :only [cl-format]])
  (:use [clojure.tools.logging :exclude [trace]])
  (:import [com.amazonaws.auth BasicAWSCredentials])
  (:import [com.amazonaws.regions Regions Region])
  (:import [com.amazonaws.services.ec2 AmazonEC2Client AmazonEC2])
  (:import [com.amazonaws.services.ec2.model
            DescribeImagesRequest DescribeInstancesRequest DescribeSecurityGroupsRequest Filter])
  (:import [com.amazonaws.services.identitymanagement AmazonIdentityManagementClient])
  (:import java.io.File))

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

;; Need a version of this in advance of IAM definitions below, for the prompt process
(defn get-user-account-number-for-prompt
  "Get the AWS account number of an iam user (as a string)"
  ([accesskey secret]
     (try
       (let [iam (AmazonIdentityManagementClient. (BasicAWSCredentials. accesskey secret))]
         (second (re-find #".*::(\d+):" (.getArn (.getUser (.getUser iam))))))
       (catch Exception x "<unknown>"))))

(defn prompt-for-credentials
  "Prompt user for keyword into cred-map for credential set to use.
  Return the (validated) keyword."
  []
  (println "The following credential files are known:")
  (let [cred-seq (seq @cred-map)
        max-key-length (reduce max (map (fn [e] (count (str (key e)))) cred-seq))]
    (doseq [entry cred-seq]
      (let [[access-key secret-key cred-file-path] (val entry)]
        (cl-format true "  ~vs  (~12a)  maps to ~a~%"
                   max-key-length
                   (key entry)
                   (get-user-account-number-for-prompt access-key secret-key)
                   (str cred-file-path)))))
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
  current-cred-key (atom nil))

(defn current-cred-map-entry
  "Return the map entry in cred-map indicating current credentials in use
   or nil if there aren't any except those imposed by the process' calling environment
  (Which you can get with environment-creds)."
  []
  (if-let [key (deref current-cred-key)]
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
  jaws process environment. The key specified must be a key in the 'cred-map'.
  (defcred (prompt-for-credentials)) may be useful."
  [key]
  (if-let [creds (key @cred-map)]
    (reset! current-cred-key key)
    (throw (Exception. (str "Invalid cred-map key: " key)))))
  
(defn choose-creds
  "Interactive selectiobn and activataion of credentials for future AWS interaction."
  []
  (defcred (prompt-for-credentials))
  (println "Current creds:" (current-cred-map-entry)))

(if-not @current-cred-key
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
        (when (= credkey @current-cred-key)
          (println "Using new AWS credentials")))))

(def ^:dynamic *region* (Region/getRegion Regions/US_EAST_1))



;;; Stupid reporting aids
(def- ^:dynamic *indent* "Number of spaces to indent each line printed" 0)

(defn- indent "Print n spaces *out*"
  ([] (indent *indent*))
  ([n] (dorun (map #(.append *out* %) (repeat n \space)))))


;;;
;;; IdentityManagement (IAM)
;;;

(defn- ^AmazonIdentityManagementClient iam
  "Return an AmazonIdentityManagementClient ready for calls."
  []
  (let [current-creds (val (current-cred-map-entry))
        creds (BasicAWSCredentials. (first current-creds) (second current-creds))
        iam (AmazonIdentityManagementClient. creds)]
    (.setRegion iam *region*)
    iam))

(defn iam-get-user
  "Get a com.amazonaws.services.identitymanagement.model.User"
  []
  (.getUser (.getUser (iam))))

(defn iam-get-user-account-number
  "Return the account number as a string from a User"
  []
  (second (re-find #".*::(\d+):" (.getArn (iam-get-user)))))
        

;;;
;;; EC2 instance queries
;;;

(defn- ^AmazonEC2Client ec2
  "Return an AmazonEC2Client instance ready for calls."
  []
  (let [current-creds (val (current-cred-map-entry))
        creds (BasicAWSCredentials. (first current-creds) (second current-creds))
        ec2 (AmazonEC2Client. creds)]
    (.setRegion ec2 *region*)
    ec2))

(defn- sort-aws-tags
  "Given a sequence of Tags, 
   sort them lexicographically by key and value names unless there is a supplied
   collection of key strings, in which case the order of keys in the collection
   will be used as the sort order for any keys in map entries.  Tag keys whose names aren't

   Example (sort-aws-tags (#Tag<:key foo :value bar> #Tag<:key Name :value fred>) [\"Name\"])
           => (#Tag<:key Name :value fred> #Tag<:key foo :value bar>)
   Normally the map with :key 'foo' would come first"
  [tag-list preferred-keys]
  (let [keysmap (if preferred-keys
                  (into {} (for [x (range (count preferred-keys))] [(nth preferred-keys x) x]))
                  {})
        comp (fn [tag1 tag2]
               (let [p1 (get keysmap (.getKey tag1)) ;'p' for priority
                     p2 (get keysmap (.getKey tag2))]
                 (cond (and p1 p2) (compare [p1 (.getValue tag1)] [p2 (.getValue tag2)])
                       p1 -1               ;prioritied key sorts < nonprioritied key
                       p2 1                ;nonprioritied key is > prioritied key
                       ;; Neither map has a priority key
                       :else (compare [(.getKey tag1) (.getValue tag1)]
                                      [(.getKey tag2) (.getValue tag2)]))))]
    (sort comp tag-list)))

(defn- squish-tags
  "Tag a list of tags and compress them into a single vector of strings of the form 'key=val'.
   E.g. [Name=this is a tag description, ...]"
  [tag-list]
  (mapv (fn [tag] (str (.getKey tag) "='" (.getValue tag) "'"))
        (sort-aws-tags tag-list ["Name" "aws:autoscaling:groupName"])))

(defn report-instances 
  "Print a one line summary of all instances in a collection of DescribeInstancesResult objects.
   If :vpc is true in options map, we print in vpc mode,
   meaning we suppress the vpcid and instead print the subnet id."
  ([describeInstancesResults] (report-instances describeInstancesResults {}))
  ([describeInstancesResults opts]
     (doseq [describeInstancesResult describeInstancesResults]
       (doseq [reservation (.getReservations describeInstancesResult)]
         (doseq [instance (.getInstances reservation)]
           ;; *TODO*: formatter for these tuples like print-maps in core.clj,
           ;; at which point <noXxx> goes away
           (indent)
           (println (.getInstanceId instance)
                    (.getImageId instance)
                    (if (:vpc opts)
                      (.getSubnetId instance)
                      (or (.getVpcId instance) "<noVpc>"))
                    (or (.getPublicDnsName instance) "<noPublicDns>")
                    (.getName (.getState instance))
                    (.getInstanceType instance)
                    (squish-tags (.getTags instance))))))))

;;;
;;; EC2 VPC
;;;

(defn print-ip-permission [ip-permission]
  (println "from port" (.getFromPort ip-permission)
           "protocol" (.getIpProtocol ip-permission)
           "ranges" (seq (.getIpRanges ip-permission))
           "to port" (.getToPort ip-permission)
           "id grps" (seq (.getUserIdGroupPairs ip-permission))))

(defn report-vpc-sg-permissions
  []
  (let [ec2 (ec2)
        describeVpcResult (.describeVpcs ec2)]
    (doseq [vpc (.getVpcs describeVpcResult)]
      (println (.getVpcId vpc)
               (.getCidrBlock vpc)
               (.getState vpc)
               (str "dflt=" (.isDefault vpc))
               (squish-tags (.getTags vpc)))
      (let [describeSecurityGroupsResult (.describeSecurityGroups
                                          ec2 (doto (DescribeSecurityGroupsRequest.)
                                                (.setFilters
                                                 [(Filter. "vpc-id" [(.getVpcId vpc)])])))]
        (doseq [sg (.getSecurityGroups describeSecurityGroupsResult)]
          (indent 2)
          (println (.getGroupId sg)
                   (.getGroupName sg)
                   (.getDescription sg)
                   (squish-tags (.getTags sg)))
          (when-let [perms (seq (.getIpPermissions sg))]
            (println "    Ingress:")
            (doseq [ipPermission perms]
              (indent 6)
              (print-ip-permission ipPermission)))
          (when-let [perms (seq (.getIpPermissionsEgress sg))]
            (println "    Egress:")
            (doseq [ipPermission perms]
              (indent 6)
              (print-ip-permission ipPermission))))))))
                     
(defn report-vpc-instances
  []
  (let [ec2 (ec2)
        describeVpcResult (.describeVpcs ec2)]
    (doseq [vpc (.getVpcs describeVpcResult)]
      (println)
      (println (.getVpcId vpc)
               (.getCidrBlock vpc)
               (.getState vpc)
               (str "dflt=" (.isDefault vpc))
               (squish-tags (.getTags vpc)))
      ;; Instances in the vpc
      (let [describeInstancesResult
            (.describeInstances
             ec2 (doto (DescribeInstancesRequest.)
                   (.setFilters [(Filter. "vpc-id" [(.getVpcId vpc)])])))]
        (binding [*indent* (+ *indent* 4)]
          (report-instances [describeInstancesResult] {:vpc true}))))))

                     
;;;
;;; EC2 Scribe account specific
;;;

(defonce scribe-production-regions
  [(Region/getRegion Regions/US_EAST_1) (Region/getRegion Regions/EU_WEST_1)
   (Region/getRegion Regions/US_WEST_2) (Region/getRegion Regions/AP_SOUTHEAST_1)])
(defonce scribe-preproduction-regions
  [(Region/getRegion Regions/US_EAST_1) (Region/getRegion Regions/EU_WEST_1)])

(defn ec2-get-production-scribe-instances
  "Return a single DescribeInstanceResult for all production scribe servers in *region*."
  []
  (.describeInstances
   (ec2)
   (doto (DescribeInstancesRequest.)
     (.setFilters
      [(Filter. "tag-value" ["scribe-relay-0" "scribe-relay-1" "scribe-relay-2"])]))))

(defn ec2-get-preproduction-scribe-instances
  "Return a single DescribeInstanceResult for all pre-production scribe servers in *region*."
  []
  (.describeInstances
   (ec2)
   (doto (DescribeInstancesRequest.)
     (.setFilters
      [(Filter. "tag-value" ["preprod-scribe-relay-0" "preprod-scribe-relay-1" "preprod-scribe-relay-2"])]))))

(defn ec2-get-all-preproduction-scribe-instances
  "Return a collection of DescribeInstanceResults for all pre-production scribe servers in all regions."
  []
  (doall
   (map (fn [region]
          (binding [*region* region]
            (ec2-get-preproduction-scribe-instances)))
        scribe-preproduction-regions)))

;;;
;;; EC2 Misc
;;;

(defn ec2-describe-account-attributes
  []
  (let [ec2 (ec2)
        result (.describeAccountAttributes ec2)]
    (into {}
          (map (fn [accountAttribute]
                 [(keyword (.getAttributeName accountAttribute))
                  (let [v (map (fn [attributeValue]
                                 (.getAttributeValue attributeValue))
                               (.getAttributeValues accountAttribute))]
                    (if (= (count v) 1)
                      (first v)
                      v))])
               (.getAccountAttributes result)))))


(defn ec2-describe-all-images
  []
  (let [ec2 (ec2)]
    (let [describe-images-result (.describeImages ec2)
          images (.getImages describe-images-result)]
      ;; For 27,900 images on bis account
      ;; This took 70 seconds.
      (println (count images) "images")
      ;; This took 74 secs.
      #_ (printlines (map #(.getImageId %) images)) ; /tmp/native-images-no-str
      ;; This took 223 secs.
      #_ (doseq [image images] (println (str image))) ; /tmp/native-images
      )))

(defn ec2-describe-some-images
  []
  (let [ec2 (ec2)
        request (DescribeImagesRequest.)]
    ;; Of 27,900+ BIS images
    (doto request                       ;set{ExecutableUsers,Filters,ImageIds,Owners}
      ;; 360 images for executable users "self"
      (.setExecutableUsers ["self"]) ; account, self, all
      ;; 7 images for owner self
      ;;(.setOwners ["self"]) ; account, amazon, aws-marketplace, self, all
      )
    (let [describe-images-result (.describeImages ec2 request)
          images (.getImages describe-images-result)]
      ;; This took 70 seconds.
      (println (count images) "images")
      ;; This took 74 secs.
      #_ (printlines (map #(.getImageId %) images)) ; /tmp/native-images-no-str
      ;; This took 223 secs.
      #_ (doseq [image images] (println (str image))) ; /tmp/native-images
      )))
          
