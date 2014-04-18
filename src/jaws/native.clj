(ns jaws.native
  (:use clojure.repl)
  (:use clojure.set)
  (:use [jdt core cl shell easyfs])
  (:use [clojure.java.io])
  (:use [clojure.pprint :only [cl-format]])
  (:use [clojure.tools.logging :exclude [trace]])
  (:import [com.amazonaws.auth BasicAWSCredentials])
  (:import [com.amazonaws.regions Regions Region])
  (:import [com.amazonaws.services.autoscaling AmazonAutoScalingClient])
  (:import [com.amazonaws.services.cloudwatch AmazonCloudWatchClient])
  (:import [com.amazonaws.services.cloudwatch.model
            DescribeAlarmsRequest])
  (:import [com.amazonaws.services.ec2 AmazonEC2Client AmazonEC2])
  (:import [com.amazonaws.services.ec2.model
            CreateImageRequest CreateTagsRequest
            DeleteSnapshotRequest DeregisterImageRequest
            DescribeImagesRequest DescribeInstancesRequest DescribeInstancesResult 
            DescribeKeyPairsRequest DescribeSecurityGroupsRequest DescribeTagsRequest
            Filter Instance InstanceAttributeName Image
            LaunchPermissionModifications LaunchPermission
            ModifyImageAttributeRequest ModifyInstanceAttributeRequest RunInstancesRequest
            StartInstancesRequest StopInstancesRequest Tag TerminateInstancesRequest])
  (:import [com.amazonaws.services.elasticloadbalancing AmazonElasticLoadBalancingClient])
  (:import [com.amazonaws.services.elasticloadbalancing.model DescribeLoadBalancersRequest])
  (:import [com.amazonaws.services.identitymanagement AmazonIdentityManagementClient])
  (:import [com.amazonaws.services.identitymanagement.model
            GetInstanceProfileRequest GetRolePolicyRequest GetRoleRequest
            ListRolePoliciesRequest])
  (:import java.io.File))

;;;
;;; Conventions
;;;
;;; Functions named 'describe-*' or 'list-*' are named after AWS methods.
;;; Functions named 'report-*' are things that use 'describe-*' results to print reports on that data.
;;; Most report functions default to one-line-per-entity formats unless other options are specified.
;;;
;;; Unless an identifier says "*-id" then the object in question is probably an AWS entity, not an entity id.
;;; I.e. 'instance' will be an Instance object, not an instance id.  Usually the documentation will clarify
;;; questions on the formal parameters, if there are any.
;;;

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

(defn cred-account-number
  "Given a keyword for credentials, return (as a string) the AWS account for the credentials, or
   '<unknown>' if the credentials aren't valid."
  [cred-keyword]
  (let [cred-info (get @cred-map cred-keyword)]
    (if-not cred-info
      (throw (Exception. (str "Credentials keyword " cred-keyword
                              " is not in the credentials map."))))
    (let [[access-key secret-key _] cred-info]
      (get-user-account-number-for-prompt access-key secret-key))))

(defn list-credentials "Print list of known credentials and account numbers" []
  (println "The following credential files are known:")
  (let [cred-seq (seq @cred-map)
        max-key-length (reduce max (map (fn [e] (count (str (key e)))) cred-seq))]
    (doseq [entry cred-seq]
      (let [[access-key secret-key cred-file-path] (val entry)]
        (cl-format true "  ~vs  (~12a)  maps to ~a~%"
                   max-key-length
                   (key entry)
                   (get-user-account-number-for-prompt access-key secret-key)
                   (str cred-file-path))))))

(defn prompt-for-credentials
  "Prompt user for keyword into cred-map for credential set to use.
  Return the (validated) keyword."
  []
  (list-credentials)
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

(defn make-aws-creds
  "Make some flavor of aws credentials such as BasicAWSCredentials from previously selected credentials
   and return them. Complain if credentials haven't been set with (choose-creds) or similar mechanism."
  []
  (if-not @current-cred-key
    (throw (Exception. "Credentials have not been set, use (choose-creds) or (defcred)")))
  (let [current-creds (val (current-cred-map-entry))]
    (BasicAWSCredentials. (first current-creds) (second current-creds))))

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

(defonce
  ^{:doc "region keyword to Regions enum mapping"}
  region-map
  (into {}
        (map (fn [region-enum]
               [(keyword (.getName region-enum))
                (Region/getRegion region-enum)])
             (seq (Regions/values)))))

(def ^{:dynamic true :doc "Keyword indicating desired region for operations that don't otherwise specify a region."}
  *region* :us-east-1)

(defn regions-for-key
  "Return a collection of regions (usually one) for some region-keyword from
   'region-map' or :all.  If region-keyword is not in region-map or :all,
   return the value of *region*.  If the keyword is :all, return all regions of
   interest (a subset of all known regions, since I don't have any accounts
   where I use all known regions yet)."
  [region-key]
  (cond (get region-map region-key)
        [(region-key region-map)]
        (= region-key :all)
        [(:us-east-1 region-map) (:eu-west-1 region-map)
         (:us-west-2 region-map) (:ap-southeast-1 region-map)]
        :else
        [(*region* region-map)]))



;;; Stupid reporting aids
(def- ^:dynamic *indent* "Number of spaces to indent each line printed" 0)

(defn- do-indent "Print n spaces *out*"
  ([] (do-indent *indent*))
  ([n] (dorun (map #(.append *out* %) (repeat n \space)))))


;;;
;;; IdentityManagement (IAM)
;;;

(defn ^AmazonIdentityManagementClient iam
  "Return an AmazonIdentityManagementClient ready for calls."
  []
  (let [iam (AmazonIdentityManagementClient. (make-aws-creds))]
    (.setRegion iam (*region* region-map))
    iam))

(defn iam-get-user-name
  "Get a the currently credential user's user name"
  []
  (.getUserName (.getUser (.getUser (iam)))))

(defn iam-get-user-account-number
  "Return the account number as a string from a User"
  []
  (second (re-find #".*::(\d+):" (.getArn (.getUser (.getUser (iam)))))))

(defn role-name-exists?
  "Return true if the specified IAM role name exists, false otherwise"
  [role-name]
  (try
    ;; This throws an exception if the role does not exist 
    (.getRole (iam) 
              (doto (GetRoleRequest.) (.setRoleName role-name)))
    true
    (catch Exception e false)))

(defn get-instance-profile
  "Return an InstanceProfile object if the indicated name exists, nil if it does not
   exist."
  [ip-name]
  (try
    (.getInstanceProfile
     (.getInstanceProfile (iam)
                          (doto (GetInstanceProfileRequest.)
                            (.setInstanceProfileName ip-name))))
    (catch Exception e nil)))

(defn get-role-policy-names
  "Retrieve all role policy names for the specified role-name, or nil if
   there aren't any.
   *TBD* May or may not need a catch block inserted for invalid role names."
  [role-name]
  (.getPolicyNames
   (.listRolePolicies
    (iam) (doto (ListRolePoliciesRequest.)
            (.setRoleName role-name)))))
    
(defn get-role-policy-documents
  "Retrieve all role policy documents for the specified role-name, or nil if there
   aren't any.
   *TBD* May or may not need a catch block inserted for invalid role names."
  [role-name]
  (map (fn [policy-name]
         ;; Note that this decodes application/x-www-form-urlencoded MIME format, 
         ;; not true RFC3986 format. It differs on only an escape or two, I suspect.
         (java.net.URLDecoder/decode 
          (.getPolicyDocument
           (.getRolePolicy
            (iam) (doto (GetRolePolicyRequest.)
                    (.setPolicyName policy-name)
                    (.setRoleName role-name)))) "UTF-8"))
       (get-role-policy-names role-name)))

(defn get-instance-profile-policy-documents
  "Retrieve all policy documents for all roles associated with an instance profile.
   Throw an exception if the instance profile name is invalid.
   Name should not be the ARN, but the general user name."
  [ip-name]
  (if-let [instanceProfile (get-instance-profile ip-name)]
    (flatten
     (map (fn [role] (get-role-policy-documents (.getRoleName role)))
          (.getRoles instanceProfile)))
    (throw (Exception. (str "InstanceProfile name '" ip-name "' does not exist.")))))

(defn report-roles
  []
  (let [result (.listRoles (iam))
        dateFormatter (java.text.SimpleDateFormat. "yyyyMMdd-HHmmssZ")
        dateFormat (fn [date] (.format dateFormatter date))]
    (if (.getIsTruncated result)
      (println "** TRUNCATED **"))      ;TODO: make sure we don't get this
    (doseq [role (.getRoles result)]
      (println (.getRoleId role)
               ;;(.getRoleName role)
               ;;(.getPath role)
               (dateFormat (.getCreateDate role))
               (.getArn role))
      ;;(println "   " (.getAssumeRolePolicyDocument role))
      )))

(defn report-instance-profiles
  []
  (let [result (.listInstanceProfiles (iam))]
    (if (.getIsTruncated result)
      (println "** TRUNCATED **"))      ;TODO: make sure we don't get this.
    (println "ProfileId ProfileName Arn Roles")
    (doseq [ip (.getInstanceProfiles result)]
      (println (.getInstanceProfileId ip)
               (.getInstanceProfileName ip)
               ;; (.getPath ip)
               (.getArn ip)
               (map (fn [role] (.getRoleName role)) (.getRoles ip))))))


;;;
;;; EC2 - General
;;;

(defn ^AmazonEC2Client ec2
  "Return an AmazonEC2Client instance ready for calls for a single (optional) region.
   'region' is a keyword defaulting to *region*."
  ([] (ec2 *region*))
  ([region]
     (let [ec2 (AmazonEC2Client. (make-aws-creds))
           region (if (instance? Region region) region (get-valid region-map region))]
       (.setRegion ec2 region)
       ec2)))


(defn key-pair-exists?
  "Return true if key pair name exists on current credentialed account, false otherwise"
  [key-pair-name]
  (let [result (.describeKeyPairs (ec2)
                (doto (DescribeKeyPairsRequest.)
                  (.setFilters [(Filter. "key-name" [key-pair-name])])))
        key-pairs (.getKeyPairs result)]
    (= (count key-pairs) 1)))

(defn security-group-name-exists?
  "Return true if the specified security group name exists, false if it does not."
  [group-name]
  ;; Throws if the gruop does not exist.
  (try 
    (let [result (.describeSecurityGroups (ec2)
                                          (doto (DescribeSecurityGroupsRequest.)
                                            (.setGroupNames [group-name])))]
      (>= (count (.getSecurityGroups result)) 1))
    true
    (catch Exception e false)))

(defn report-tags
  "Print tag information for any specific EC2 entity that can have tags.
   Specify the entity ID."
  [entity]
  (let [result (.describeTags (ec2)
                 (doto (DescribeTagsRequest.)
                   (.setFilters [(Filter. "resource-id" [entity])])))
        tagDescriptions (.getTags result)]
    (if (empty? tagDescriptions)
      (println "No tags exist for" entity)
      (doseq [tagDescription tagDescriptions]
        (println (.getResourceId tagDescription)
                 (.getKey tagDescription)
                 (.getResourceType tagDescription)
                 (.getValue tagDescription))))))
  
(defn create-tags
  "Create tags for any specific EC2 entity that can have tags.
   Specify the entity ID (or list of entity IDs) and a map of tag key/value pairs.
   Strings and vals are assumed strings, however keywords are acceptable
   in which case their names will be used.
   Returns nil."
  [entity tag-map]
  {:pre [(map? tag-map)]}
  (let [strify (fn [x] (if (keyword? x) (name x) (str x)))
        tags (map (fn [e] (Tag. (strify (key e)) (strify (val e)))) tag-map)]
    (.createTags (ec2) (CreateTagsRequest. (listify entity) tags))))
    

;;;
;;; EC2 - instance queries
;;;
(declare describe-instances)

(def instance-state-code-map "Map of InstanceState codes to keywords"
  {0 :pending, 16 :running, 32 :shutting-down, 48 :terminated, 64 :stopping, 80 :stopped})

(defmulti  instance-state
    "Retrieve instance state for an EC2 instance as a keyword, e.g. :running.
     Note that an instance-id will cause a refetch of state, while an Instance
     object merely decodes the state already in memory (which will not change
     across successfive calls)."
    class)
(defmethod instance-state String [instance-id]
  (instance-state (first (describe-instances :ids instance-id))))
(defmethod instance-state Instance [instance]
  (get instance-state-code-map (.getCode (.getState instance)) :unknown-state-code))

(defmulti  wait-for-instance-state
  "Wait for an instance to reach the designated instance state.

   Instance may be an instance or instance ID.
   State should be one of :running :terminated or :stopped
    (and not one of the transient states).

   Note that state is re-fetched for the instance call until the target
   state is reached.

   Optional keyword args include:
   :verbose - print a 'waiting for <id> to enter the <y> state' message with a dot
              every 5 seconds.
   Returns nil."
  (fn [& args] (class (first args))))
(defmethod wait-for-instance-state Instance [instance state & args]
  (wait-for-instance-state (.getInstanceId instance) state))
(defmethod wait-for-instance-state String [instance-id state & {:keys [verbose]}]
  {:pre [(get #{:running :terminated :stopped} state)]}
  (when verbose
    (let [initial-state (instance-state instance-id)]
      (if-not (= initial-state state)
        (println "Waiting for" initial-state "instance" instance-id "to enter the" state "state"))))
  (while (not= (instance-state instance-id) state)
    (Thread/sleep 5000)
    (if verbose
      (do (print ".") (flush))))
  (if verbose
    (println)))
  


(defmulti  instance-public-dns-name
  "Retrieve the public dns name for an instance or instance id,
   return nil if there isn't one.  Note that this information isn't available at all
   until the instance is in the :running state, and maybe not even then for VPC instances."
  class)
(defmethod instance-public-dns-name String [instance-id]
  (instance-public-dns-name (first (describe-instances :ids instance-id))))
(defmethod instance-public-dns-name Instance [instance]
  (let [dns-name (.getPublicDnsName instance)]
    (and (> (count dns-name) 0)
         dns-name)))

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
  (mapv (fn [tag] (str (.getKey tag) "=" (.getValue tag)))
        (sort-aws-tags tag-list ["Name" "aws:autoscaling:groupName"])))

(defn instance-volume-ids
  "Return a collection of ebs volume IDs attached to an Instance object.
   Often called implicitly via:
   (report-instances :instances (describe-instances :tag-regex #\"(?i)created\")
                                :fields #{:VolumeIds})"
  [instance]
  (->> (.getBlockDeviceMappings instance)
       (map (fn [mapping] (.getEbs mapping)))
       (map (fn [dev] (.getVolumeId dev)))))

(defn describeInstancesResult->instances
  "Convert DescribeInsancesResult objects to a sequence of instances.
   The argument may be a singleton DescribeInstancesResult or a collection of them."
  [results]
  (->> (seqify results)
       flatten
       (map (fn [describeInstancesResult] (seq (.getReservations describeInstancesResult))))
       flatten
       (map (fn [reservation] (seq (.getInstances reservation))))
       flatten))

;; Some stupid report printing functions & macros
(defn- pu "print unquoted/friendly, ie. ~a" [x] (print x) (print " "))
(defn- pq "print quoted/readable, ie. ~s" [x] (pr x) (print " "))
(defmacro pif
  "print val using print-fn if test is true, avoid computing val more than once"
  [test val print-fn]
  `(if ~test
     (let [val# ~val]
       (~print-fn val#))))

;; *TBD*: might like to know what AutoScalingLaunchConfig was used to launch an instance, 
;; but this is only available via an DescribeAutoScalingInstancesResult.
;; *TBD*: List valid keywords for fields if an improper one is given, right now we silently ignore it.
(defn report-instances 
  "Print a information about instances.
   The default is to print one line of information per instance, unless options
   are specified for other details.

   Options:
   :indent all lines with the indicated (minimum) number of leading spaces
           indentation desired (default zero).  note that secondary lines (if
           more than one line per instance is printed) are indented an
           additional indent-incr spaces.
   :indent-incr amount to additionally indent secondary data lines (for
                options where more than one line per instance is printed. Default 2.
   :data A DescribeInstancesResult object or collection of those objects to
         be reported upon.  If neither this nor :instances is specified,
         (describe-instances) is called to retrieve data.
   :instances An Instance collection of instances.  If neither this nor :data
              is speciied, (describe-instances is called to retrieve data.
              If both are specified, the resulting instances from each field are used
              (all together).  Note that you can turn instance IDs to instances
              via 'describe-instances'.
   :ids An instance ID or collection thereof, passed to 'describe-instances'.
   :region a region keyword from 'region-map', or :all, in which case
           iff :data is unspecified, data will be fetched from all regions.
           :region is ignored if :data is specified.
   :fields Set of fields (information) to display in addition to instance id.
           Defaults to: #{:ImageId :VpcId :SubnetId :PublicDnsName :KeyName :State :InstanceType :SecurityGroups :Tags}
           Additional fields include: :VolumeIds, :InstanceProfile, :LaunchTime, :StoreType
           :PrivateIpAddress :PrivateDnsName :PublicIpAddress.
   :include Set of additional fields to display, defaults to #{}
   :exclude Set of fields to exclude from the display, defaults to #{}.
   :split-after A field keyword, or collection of field keywords, after which a 'println' and indent
                will occur to break the report into multiple lines per instance.
                By default there is only one line per instance for easier output grepping.
                Rather pointless if you use the last field as a split field, unless you want a blank line
                between each instance' report.  JDT likes :InstanceType for this keyword.
   Note that presently you can't specify the order of fields."
  [& {:keys [data instances ids vpc-mode region indent indent-incr fields include exclude split-after]
      :or {indent *indent* indent-incr 2
           fields #{:ImageId :VpcId :SubnetId :PublicDnsName :KeyName :State :InstanceType :SecurityGroups :Tags}
           include #{} exclude #{} }}]
  {:pre [(set? include) (set? exclude) (set? fields)]}
  (let [instances1 (and data (describeInstancesResult->instances data))
        instances2 (and instances (seqify instances))
        instances2a (and ids (describe-instances :ids ids))
        instances3 (concat instances1 instances2 instances2a)
        instances4 (if (empty? instances3)
                       (describeInstancesResult->instances
                        (map #(.describeInstances (ec2 %))
                             (regions-for-key region)))
                       instances3)
        fields (difference (union fields include) exclude)
        split-after (into #{} (seqify split-after))
        sp (fn [x] (when (split-after x)
                     (println)
                     (do-indent(+ indent indent-incr))))     ;split if necessary
        xpr (fn [key val printfn]         ;print and maybe split, use 'pif' or similar?
              (when (get fields key)
                (printfn val)
                (sp key)))]
    (doseq [instance instances4]
      (do-indent indent)
      (pu (.getInstanceId instance))
      ;; Convert to pure iteration on fields and reflection call? 
      ;; Also note that xpr as function forces value valuation where as
      ;; xpr as macro could avoid evaluating all these reflective calls
      ;; even if we don't print them.
      (xpr :ImageId (.getImageId instance) pu)
      (xpr :VpcId (or (.getVpcId instance) "<noVpc>") pu)
      (xpr :SubnetId (or (.getSubnetId instance) "<noSubnet>") pu)
      (xpr :PublicDnsName (empty-string-alternative (.getPublicDnsName instance) "<noPublicDns>") pu)
      (xpr :PublicIpAddress (.getPublicIpAddress instance) pu)
      (xpr :PrivateDnsName (empty-string-alternative (.getPrivateDnsName instance) "<noPrivateDns>") pu)
      (xpr :PrivateIpAddress (.getPrivateIpAddress instance) pu)
      (xpr :KeyName (.getKeyName instance) pu)
      (xpr :State (.getName (.getState instance)) pu)
      (xpr :LaunchTime (str (.getLaunchTime instance)) pu)
      (xpr :InstanceType (.getInstanceType instance) pu)
      (xpr :StoreType (.getRootDeviceType instance) pu) ; "ebs" or "instance-store"
      (xpr :InstanceProfile
           (if-let [ip (.getIamInstanceProfile instance)]
             (.getArn ip)
             "<noInstanceProfile>")
           pu)
      (xpr :SecurityGroups (map #(.getGroupName %) (.getSecurityGroups instance)) pu)
      (xpr :Tags (squish-tags (.getTags instance)) pq)
      (xpr :VolumeIds (instance-volume-ids instance) pu)
      (println))))

(defn- tag-regex-find-fn 
  "Return a function of one argument that takes calls .getTags on the argument
   the result of re-find if (re-find regex <x>) is true for either the tag key
   or the tag value for any tag returned.  re-find is called on the key first, then the
   value, it is not called on the value if the key test returns a logically
   true value."
  [regex]
  {:pre [(instance? java.util.regex.Pattern regex)]}
  (fn [taggable]
    (some (fn [tag]
            (or (re-find regex (.getKey tag))
                (re-find regex (.getValue tag))))
          (seq (.getTags taggable)))))

;; *TODO*: note that Filter _values_ can have '*' (zero or more chars) and '?' (one or more chars), as per
;; http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Filtering.html#Filtering_Resources_CLI
;; Filter value matching is case sensitive (hence pretty limited, particularly since there's no disjunction).
;; Note: wildcard and baskslash chars must be escaped with backslashes.
;; *TBD*: Whether to change tag-regex behavior to re-match instead of re-find
;; *TBD*: need filters of some kind (pre or post) that match any interesting field,
;; not just tags. (userdata, description, instance name, sg names, etc)
(defn describe-instances
  "Retrieve zero or more Instances with various filters and regions applied.
   Returns a collection that can be fed as :data to 'report-instances', e.g.
   (report-instances :instances (describe-instances :tag-regex #\"(?i)created\"))
   Options:
   :region a region keyword from 'region-map', or :all to operate on all regions.
   :ids a string instance ID, or collection/sequence of same, specifying specific instances
        whose data should be retrieved.
   :tag-regex a regular expression (java.util.regex.Pattern) applied to tag names and
              values as a filter.  Instances lacking the regex will not be returned.
              Instances are only returned if the regex passes a 'find', not a
              'matches' operation. '(?i)' may be useful in your regex to ignore case.
              Note that tag regexes must filter tags after retrieval from amazon."
  [& {:keys [region tag-regex ids]}]
  (let [regions (regions-for-key region)
        fetch-fn (if ids
                   (if (> (count ids) 0)
                     (fn [region] (.describeInstances (ec2 region)
                                                      (doto (DescribeInstancesRequest.)
                                                        (.setInstanceIds (seqify ids)))))
                     (constantly nil))
                   (fn [region] (.describeInstances (ec2 region))))
        tag-regex-fn (if tag-regex (tag-regex-find-fn tag-regex) identity)]
    (->> (filter identity (map fetch-fn regions)) ;filter nils
         flatten
         (map (fn [descInsRes] (seq (.getReservations descInsRes))))
         flatten
         (map (fn [reservation] (seq (.getInstances reservation))))
         flatten
         (filter tag-regex-fn)
         )))

(defn run-instances
  "Start new instances from a specificed AMI.  *FINISH*: this is a work in progress.
   Returns a sequence of instance ids created.
   
   Arguments:
   ami-id  The image id to use.
   :keyname the name of the key pair to use.
   :type the instance type to use ({m1,m3,c1}.{small,medium,[x]large}, etc)
         *TODO* online help to list options for this please.
   :group-ids security group id or collection of ids to use for secrity groups
   :group-names security group name or collection of names to use for secrity groups
                (ec2-classic, default-vpc only, can use with group-ids as well)
   :min    minimum number of instances to run
   :max    maximum number of instances to run
   :wait   true if this function should not exit until all instances have started.
           Note that they instances may not yet be responsive just because they're 'running'
           and have a DNS address.  YMMV.
   :region a region keyword from 'region-map' to override *region*."
  [ami-id & {:keys [keyname type group-ids group-names min max wait region]
             :or {region *region* type "t1.micro" min 1 max 1}}]
  {:pre [(not (= region :all))]}
  (let [min (int min)
        max (int max)
        request (RunInstancesRequest. ami-id min max)]
    (.setInstanceType request type)
    (if keyname (.setKeyName request keyname))
    (if group-ids (.setSecurityGroupIds request (listify group-ids)))
    (if group-names (.setSecurityGroups request (listify group-names)))
    (let [reservation (->> (.runInstances (ec2 region) request)
                           (.getReservation))
          instances (seq (.getInstances reservation))
          instance-ids (map #(.getInstanceId %) instances)
          user-name (iam-get-user-name)]
      (cl-format true "Instance~p created: ~s~%" (count instances) instance-ids)
      (doseq [id instance-ids]
        (create-tags id {:created-by user-name})) ; *TBD*: let caller pass additional tags
      (if wait
        (doseq [id instance-ids]
          (wait-for-instance-state id :running :verbose true)))
      instance-ids)))

(defn start-instances
  "Start one or more stopped instances.
   ids     a string instance ID or collection/sequence of same specifying specific instances
           to be started.
   :wait   true if this function should not exit until all instances have started.
           Note that they instances may not yet be responsive just because they're 'running'
           and have a DNS address.  YMMV.
   :region a region keyword from 'region-map' to override *region*."
  [ids & {:keys [region wait]
          :or {region *region*}}]
  {:pre [(not (= region :all))]}
  (let [ids (listify ids)]
    (doseq [instanceStateChange 
            (->> (.startInstances (ec2 region) (StartInstancesRequest. ids))
                 (.getStartingInstances))]
      (println (.getInstanceId instanceStateChange)
               (.getName (.getPreviousState instanceStateChange))
               "=>"
               (.getName (.getCurrentState instanceStateChange))))
    (if wait
      (doseq [id ids]
        (wait-for-instance-state id :running :verbose true)))))


(defn stop-instances
  "Stop one or more instances, waiting if requested.
   ids     a string instance ID or collection/sequence of same specifying specific instances
           to be deleted.
   :wait   true if this function should not exit until all instances have stopped.
   :region a region keyword from 'region-map' to override *region*."
  [ids & {:keys [region wait]
          :or {region *region*}}]
  {:pre [(not (= region :all))]}
  (let [ids (listify ids)]
    (doseq [instanceStateChange 
            (->> (.stopInstances (ec2 region) (StopInstancesRequest. ids))
                 (.getStoppingInstances))]
      (println (.getInstanceId instanceStateChange)
               (.getName (.getPreviousState instanceStateChange))
               "=>"
               (.getName (.getCurrentState instanceStateChange))))
    (if wait
      (doseq [id ids]
        (wait-for-instance-state id :stopped :verbose true)))))

;; *TODO*: Add a :wait keyword like we did for stop-instances
(defn terminate-instances
  "Terminate one or more instances.
   ids     a string instance ID or collection/sequence of same specifying specific instances
           to be deleted.
   :region a region keyword from 'region-map' to override *region*.
   :force  if true, ensure that we can disable the instance via termination APIs
           (i.e cancel 'DisableApiTermination' status)."
  [ids & {:keys [region force]
          :or {region *region*}}]
  {:pre [(not (= region :all))]}
  (let [ids (listify ids)]
    (if force
      (doseq [id ids]
        (.modifyInstanceAttribute (ec2 region)
         (doto (ModifyInstanceAttributeRequest.
                id InstanceAttributeName/DisableApiTermination)
           (.setValue "false")))))
    (doseq [instanceStateChange 
            (->> (.terminateInstances (ec2 region) (TerminateInstancesRequest. ids))
                 (.getTerminatingInstances))]
      (println (.getInstanceId instanceStateChange)
               (.getName (.getPreviousState instanceStateChange))
               "=>"
               (.getName (.getCurrentState instanceStateChange))))))

;;;
;;; EC2 Security groups
;;; 

(defn report-sgs
  "Print a one line summary (unless options specify otherwise)
   of security groups for one or more DescribeSecurityGroupsResults instances."
;; *TODO*: options for region(? - and including :all) and and for :ingress :egress
;; :region may be a standard option for all things that roll an ec2
;; maybe also some :regex filtering options, though if we just return tuples
;; caller can do that other ways
  ([] (report-sgs [(.describeSecurityGroups (ec2))]))
  ([describeSecurityGroupsResults] (report-sgs describeSecurityGroupsResults {}))
  ([describeSecurityGroupsResults opts]
     (doseq [describeSecurityGroupsResult describeSecurityGroupsResults]
       (doseq [sg (.getSecurityGroups describeSecurityGroupsResult)]
         (cl-format true "~a ~a ~a ~a ~a ~s~%"
                    (.getGroupId sg)
                    (.getGroupName sg)
                    (.getOwnerId sg)
                    (or (.getVpcId sg) "<novpc>")
                    (squish-tags (.getTags sg))
                    (.getDescription sg))))))


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
          (do-indent 2)
          (println (.getGroupId sg)
                   (.getGroupName sg)
                   (.getDescription sg)
                   (squish-tags (.getTags sg)))
          (when-let [perms (seq (.getIpPermissions sg))]
            (println "    Ingress:")
            (doseq [ipPermission perms]
              (do-indent 6)
              (print-ip-permission ipPermission)))
          (when-let [perms (seq (.getIpPermissionsEgress sg))]
            (println "    Egress:")
            (doseq [ipPermission perms]
              (do-indent 6)
              (print-ip-permission ipPermission))))))))
                     
(defn report-vpc-instances
  "Print summary of instances in vpcs, grouped by vpc."
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
          (report-instances :data describeInstancesResult :exclude #{:VpcId} :include #{:PrivateIpAddress}))))))

;;;
;;; Auto-scaling stuff
;;;

;;; NOTE: while an auto-scaling-group has one currently associated launch config,
;;; it may have instances running associated with "old" launch configs that are not longer the current one for the
;;; ASG (look at the ASG instances, and the launch configs of those instances, and you'll see the launch configs that aren't the
;;; current ASG LC.)

(defn ^AmazonAutoScalingClient asc
  "Return an AmazonAutoScalingCLient instance ready for calls for a single (optional) region.
   'region' is a keyword defaulting to *region*."
  ([] (asc *region*))
  ([region]
     (let [asc (AmazonAutoScalingClient. (make-aws-creds))
           region (if (instance? Region region) region (get-valid region-map region))]
       (.setRegion asc region)
       asc)))

(defn describe-auto-scaling-groups []
  "Return a list of AutoScalingGroup instances.  *TBD* Not sure what to do with tokens. and possibly incomplete results."
  (.getAutoScalingGroups (.describeAutoScalingGroups (asc))))
  
(defn report-auto-scaling-groups []
  "Print one line summary of AutoScalingGroup instances.
   *TODO*: There's a lot of useful data here we don't report on right now."
  (doseq [group (describe-auto-scaling-groups)]
    (println (.getAutoScalingGroupName group)
             "LC:" (.getLaunchConfigurationName group)
             "LBs:" (seq (.getLoadBalancerNames group))
             "VpcZid:" (.getVPCZoneIdentifier group)
             "Status:" (.getStatus group)
             (map #(.getInstanceId %) (.getInstances group))
             "Susp:" (map #(.getProcessName %) (.getSuspendedProcesses group))
             (squish-tags (.getTags group)))))

(defn dump-auto-scaling-groups []
  "Print a hierarchical report of auto-scaling groups, their instances, launch configurations, etc."
  ;; Get a map of instance->launch config data
  (let [autoScalingInstanceDetails (.getAutoScalingInstances (.describeAutoScalingInstances (asc)))
        asgroupnames->lc-names
        (apply (partial merge-with union)
               (map (fn [asid] {(.getAutoScalingGroupName asid) #{(.getLaunchConfigurationName asid)}})
                    autoScalingInstanceDetails))
        lc-names->as-group-names
        (apply (partial merge-with union)
               (map (fn [asid] {(.getLaunchConfigurationName asid) #{(.getAutoScalingGroupName asid)}})
                    autoScalingInstanceDetails))
        lc-names->instance-ids
        (apply (partial merge-with union)
               (map (fn [asid] {(.getLaunchConfigurationName asid) #{(.getInstanceId asid)}})
                    autoScalingInstanceDetails))
        instance-ids->lc-names
        (apply (partial merge-with union)
               (map (fn [asid] {(.getInstanceId asid) #{(.getLaunchConfigurationName asid)}})
                    autoScalingInstanceDetails))
        ri (fn [ids]
             (report-instances :ids ids :indent 4 :include #{:PrivateIpAddress}
                               :split-after :InstanceType))
        auto-scaling-groups (describe-auto-scaling-groups)]
    (doseq [group auto-scaling-groups]
      (let [as-group-name (.getAutoScalingGroupName group)]
        (println "AutoScalingGroup:" as-group-name)
        (doseq [launch-config-name (get asgroupnames->lc-names as-group-name)]
          (print "  Launch Configuration:" launch-config-name)
          (if (= launch-config-name (.getLaunchConfigurationName group))
            (println "  [Active]")
            (println "  [INACTIVE]"))
          ;; Intersect LC->instances with ASG->instances in case they don't map 1:1
          (ri (intersection
               (into #{} (get lc-names->instance-ids launch-config-name))
               (into #{} (map #(.getInstanceId %) (.getInstances group))))))
        ;; Paranoid: check for asg reported instances not in above launch configurations
        (let [asg-instances (.getInstances group)
              instance-ids (map #(.getInstanceId %) asg-instances)
              ids-without-lc-key (filter (fn [id] (not (get instance-ids->lc-names id)))
                                         instance-ids)]
          (when (not-empty? ids-without-lc-key)
            (println)
            (println "  ** AutoScalingGroup instances not in the above Launch Configurations. **")
            (ri ids-without-lc-key)))))

    ;; Print out any launch configs not mentioned as part of auto scaling groups above
    (let [all-launch-configurations (.getLaunchConfigurations (.describeLaunchConfigurations (asc)))
          lc-names-not-in-as-groups
          (filter (fn [lcname] (not (get lc-names->as-group-names lcname)))
                  (map #(.getLaunchConfigurationName %) all-launch-configurations))]
      (unless (empty? lc-names-not-in-as-groups)
              (println)
              ;; Unless the LC was created after we queried the ASG's above, a timing hole
              (println "** Unused Launch Configurations **")
              (let [lc-name->launch-configurations
                    ;; This is in case there are multiple orphaned launch configurations with the same name,
                    ;; hopefully that's not possible, but only Amazon knows.
                    (apply (partial merge-with concat)
                           (map (fn [lc] {(.getLaunchConfigurationName lc) [lc]})
                                all-launch-configurations))]
                (doseq [lc-name lc-names-not-in-as-groups]
                  (doseq [lc (get lc-name->launch-configurations lc-name)]
                    (println " " lc-name " created:" (str (.getCreatedTime lc)))
                    (println "   " (.getLaunchConfigurationARN lc))
                    (println "    ImageId:" (.getImageId lc) " HasPublicIP:" (.getAssociatePublicIpAddress lc))
                    (println "    InstanceProfile:" (.getIamInstanceProfile lc) " KeyPairName:" (.getKeyName lc)
                             " InstanceType:" (.getInstanceType lc))
                    (println "    SecurityGroups:" (seq (.getSecurityGroups lc))))))))))


                     
;;;
;;; EC2 Images
;;;

(defn image-state
  "Fetch image state for an image id.
   Returns one of :available, :deregistered, or :pending."
  [image-id]
  (->> (.describeImages
        (ec2) 
        (doto (DescribeImagesRequest.)
          (.setImageIds (list image-id))))
       .getImages
       first
       .getState
       keyword))

(defmulti  wait-for-image-state
  "Wait for an image (AMI) to reach the designated state.

   Image may be an Image or Image ID.
   State should be one of :available or :deregistered.

   Note that state is re-fetched for the image call until the target
   state is reached, this doesn't just check image state on a previously fetched Image.

   Optional keyword args include:
   :verbose - print a 'waiting for <id> to enter the <y> state' message with a dot
              every 5 seconds.
   Returns nil."
  (fn [& args] (class (first args))))
(defmethod wait-for-image-state Image [image state & args]
  (wait-for-image-state (.getImageId image) state))
(defmethod wait-for-image-state String [image-id state & {:keys [verbose]}]
  {:pre [(get #{:available :deregistered} state)]}
  (when verbose
    (let [initial-state (image-state image-id)]
      (if-not (= initial-state state)
        (println "Waiting for" initial-state "image" image-id
                 "to enter the" state "state"))))
  (while (not= (image-state image-id) state)
    (Thread/sleep 5000)
    (if verbose
      (do (print ".") (flush))))
  (if verbose
    (println)))


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
          
(defn keys-n-stuff->strings [seq]
  (map (fn [thing]
         (cond (keyword? thing) (name thing)
               (string? thing) thing
               :else (str thing)))
       seq))

(defn describe-images
  "Return a list of Image objects.  Beware calling this without IDs or other filters.
   Options:
   :ids - an image id or seq of image ids.
   :owned-by - Can be one of the following, or a list of the following:
               :self or \"self\", return only images owned by self, where self is the sender of the request,
               :all or \"all\",
               a string or number specifying an aws account ID.
   :exec-by - Return only images executable by the value of this arg because of explicit launch permissions
              Can be one of the following, or a list of the following:
              :self or \"self\", where self is the sender of the request,
              :all or \"all\",
              or a string or numeric AWS account ID."
  ;; *TODO: Filters
  [& {:keys [ids owned-by exec-by]}]
  (let [request (DescribeImagesRequest.)]
    (if ids (.setImageIds request (listify ids)))
    (if owned-by (.setOwners request (keys-n-stuff->strings (listify owned-by))))
    (if exec-by (.setExecutableUsers request (keys-n-stuff->strings (listify exec-by))))
    (seq (.getImages (.describeImages (ec2) request)))))

(defn report-images
  "Report on zero or more Image instances,
   fetch them if none are specified as with 'describe-images'.

   CAUTION: without filters, this call returns a lot of data and can take a long time.
   :owned-by :self and/or :exec-by :self is recommended to do some basic filtering if
   you don't specify specific images/ids.

   :images - an Image or collection of Image instances, optional.

   :fields - set of fields (information) to display in addition to image id.
             Defaults to: #{:ImageLocation :Architecture :ImageType :StoreType
                      :Platform :State :Description :Tags}
             Additional fields include: :Name, :Owner :Devices
   :include Set of additional fields to display, defaults to #{}
   :exclude Set of fields to exclude from the display, defaults to #{}.

   The following filtering keywords are as documented in 'describe-images':
   :ids, :owned-by, :exec-by.

   Returns nil."
  [& {:keys [images ids owned-by exec-by fields include exclude]
      :or {fields #{:ImageLocation :Architecture :ImageType :StoreType :Platform :State
                    :Description :Tags}
           include #{} exclude #{}}}]
  {:pre [(set? include) (set? exclude) (set? fields)]}
   
  (let [fetched-images (if (or (not images) ids)
                         (describe-images :ids ids :owned-by owned-by :exec-by exec-by))
        images (concat (listify images) fetched-images)
        fields (difference (union fields include) exclude)]
    (doseq [image images]
      (pu (.getImageId image))
      ;; image location contains account (owner id) and name
      ;; making Name and OwnerId info redundant ... ?  Seems like it
      (pif (:ImageLocation fields) (.getImageLocation image) pq)
      (pif (:Name fields) (.getName image) pq)
      (pif (:Owner fields) (.getOwnerId image) pu)
      (pif (:Architecture fields) (.getArchitecture image) pu)
      (pif (:ImageType fields) (.getImageType image) pu)
      (pif (:Platform fields) 
           (empty-string-alternative (.getPlatform image) "sane") pu)
      ;; Note that .getRootDeviceName seems to be nil for instance stores
      (pif (:StoreType fields) (.getRootDeviceType image) pu) ; "ebs" or "instance-store"
      (pif (:State fields) (.getState image) pu)
      (pif (:Description fields) (.getDescription image) pq)
      (pif (:Tags fields) (squish-tags (.getTags image)) pq)
      (println)
      (when (:Devices fields)
        (doseq [blockDeviceMapping (.getBlockDeviceMappings image)]
          (print " " (.getDeviceName blockDeviceMapping)
                 (.getVirtualName blockDeviceMapping)
                 (.getNoDevice blockDeviceMapping))
          (if-let [ebsBlockDevice (.getEbs blockDeviceMapping)] ; m/b null
            (do
              (print " ")
              (println (.getSnapshotId ebsBlockDevice)
                       (.getVolumeType ebsBlockDevice)
                       (.getVolumeSize ebsBlockDevice)
                       (.getIops ebsBlockDevice)
                       (.getDeleteOnTermination ebsBlockDevice)))
            (println)))))))
      

(defn create-image
  "Create an EBS backed AMI from a running or stopped EBS-backed instance.
   Name is 3-128 alphanumeric characters and any of [-()./_].
   Returns the resulting image-id.
   Options:
   :quiet     - if true, do not print the resulting image ID to *out*.
   :no-reboot - if true do not stop and reboot the instance. By default
                instances are stopped for the image creation, then restarted.
                TBD: What happens if the instance is already stopped?  Is it restarted?
                I usually specify :no-reboot true on a stopped instance to be sure.
   :description - a description of the instance."
  [instance-id name
   & {:keys [description no-reboot quiet]}]
  (let [request (CreateImageRequest. instance-id name)]
    (if no-reboot (.setNoReboot request true))
    (if description (.setDescription request description))
    (let [result (.createImage (ec2) request)]
      (unless quiet (println "Image created is" (.getImageId result)))
      (.getImageId result))))

(defn image-add-launch-permission
  "Add accounts to an image' launch permissions.  Returns nil.
   Accounts should be AWS account numbers (as strings or numbers).
   This function is a currently a shortcut bandaid for a more
   flexible interface to the modifyImageAttribute API."
  [image-id & accounts]
  {:pre [(not (empty? accounts)) (string? image-id)]}
  ;; See "DescribeImageAttributeRequest" docs for valid attributes, presently
  ;; description, kernel, ramdisk, launchPermission, productCodes, blockDeviceMapping
  (let [request (ModifyImageAttributeRequest.)
        launch-mods (LaunchPermissionModifications.)]
    (doto launch-mods
      (.setAdd (map (fn [account]
                      (doto (LaunchPermission.)
                        (.setUserId (str account))))
                    accounts)))
    (doto request
      (.setImageId image-id)
      (.setLaunchPermission launch-mods))
    (.modifyImageAttribute (ec2) request)))

;; *TBD* How does one delete an instance store AMI?
;; Answer here: http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/deregister-ami.html
;; (Good link to have for delete-image logic, fyi).
;; See also: https://aws.amazon.com/articles/Amazon-EC2/637
;; Note that multiple AMIs can be registered from a single bundle in S3.
;; In short: deregister, then  deleteBundle.  *TODO*
;; *HELP*: There is no deleteBundle API or ec2-delete-bundle operation as referenced in the page.  Hmmm
;; (may be under "AMI tools", not the EC2 CLI tools).  Or it's basically just S3 file deletion.
;; Ruby code. Gets list of files to delete from the manifest file, then deletes them.
;;
;; *TODO*: there's some additional smarts we can put in here below (things we don't deal
;; with, see function code).
;;
;; Also, it would be nice to warn and require a :force if the image to be deleted
;; is associated with EC2 instances on the account (running or not).
(defn delete-image
  "To delete an image, you need to deregister the image and delete the snapshot
   behind it. The snapshot is found in the BlockDeviceMappings for the image.
   This function provides that capability.
   *TODO*: Doesn't presently support instance-stores, needs a deleteBundle for those."
  [image-id]
  {:pre [image-id]}
  (let [images (describe-images :ids image-id)]
    (if (empty? images)
      (throw (Exception. (str "Image " image-id " does not appear to exist"))))
    (let [image (first images)
          blockDeviceMappings (.getBlockDeviceMappings image)]
      (if (empty? blockDeviceMappings)
        (throw (Exception. (str "Image " image-id " does not appear to have block device mappings."
                                " I am unsure of how to delete it."))))
      (let [ebsBlockDevices (filter identity (map #(.getEbs %) blockDeviceMappings))]
        (if (> (count ebsBlockDevices) 1)
          (throw (Exception. (str "Image " image-id " has more than one EBS block device mapping."
                                  " I don't deal with that right now, perhaps I should report on them and ignore them.  *TBD*"))))
        (if (= (count ebsBlockDevices) 0)
          (throw (Exception. (str "Image " image-id " has no EBS block device mappings"
                                  " I don't know how to delete such an image."))))
        (let [snapshot-id (.getSnapshotId (first ebsBlockDevices))]
          (println)
          (println "The following image will be deregistered, and the associated EBS snapshot deleted.")
          (report-images :images images :include #{:Devices})
          (.deregisterImage (ec2) (DeregisterImageRequest. image-id))
          (println "... image" image-id "deregistered")
          (.deleteSnapshot (ec2) (DeleteSnapshotRequest. snapshot-id))
          (println "... snapshot" snapshot-id "deleted")
          (println "Image deletion complete."))))))

;;;
;;; ELB
;;;

(defn ^AmazonElasticLoadBalancingClient elb
  "Return an AmazonElasticLoadBalancingClient ready for calls for a single (optional) region.
  'region' is a keyword defaulting to *region*."
  ([] (elb *region*))
  ([region]
     (let [elb (AmazonElasticLoadBalancingClient. (make-aws-creds))
           region (if (instance? Region region) region (get-valid region-map region))]
       (.setRegion elb region)
       elb)))

(defn describe-elbs
  "Return LoadBalancerDescription objects for ELB's.  If one or more names are specified, describe only those ELB's."
  [& elb-names]
  (.getLoadBalancerDescriptions
   (if elb-names
     (.describeLoadBalancers (elb) (DescribeLoadBalancersRequest. elb-names))
     (.describeLoadBalancers (elb)))))

;; *TODO*: replace jdt.core 'not-empty?' with this
(defn better-not-empty?
  "Returns coll if the specified collection or sequence is not empty, otherwise nil."
  [coll]
  (if (empty? coll)
    nil
    coll))

(defn report-elbs
  "Print information about elastic load balancers.  Returns nil.
   :descs -if specified, one or a collection of LoadBalancerDescription objects as if from 'describe-elbs'.
   :names -if specified, one or a colelction of ELB names, passed to 'describe-elbs'.
           If neither :names nor :descs is specified, we call (describe-elbs) for descriptions.
   :fields - A set that defaults to the following:
           #{:Name :DnsName :Vpc :Scheme :Subnets :Sgs :SourceSg}
           and may also include: :HostedZoneName :HostedZoneId :Azs :Ctime :Backends :Instances :Listeners :Policies.
   :include - A set of additional fields to include as described with :fields.
   :exclude - A set of fields to exclude as described with :fields."
  [& {:keys [descs names fields include exclude]
      :or {fields #{:Name :Vpc :DnsName :Scheme :Subnets :Sgs :SourceSg}
           include #{} exclude #{}}}]
  {:pre [(set? include) (set? exclude) (set? fields)]}
  (let [names (listify names)
        descs (listify descs)
        descs (or (better-not-empty?
                   (concat (and names (apply describe-elbs names)) descs))
                  (describe-elbs))
        fields (difference (union fields include) exclude)]
    (doseq [desc descs]
      (pq (.getLoadBalancerName desc))
      (pif (:Vpc fields) (empty-string-alternative (.getVPCId desc) "<noVpc>") pu)
      (pif (:DnsName fields) (.getDNSName desc) pu)
      ;; Note that the zone name is often the same as dns name.
      (pif (:HostedZoneName fields) (.getCanonicalHostedZoneName desc) pq)
      (pif (:HostedZoneId fields) (.getCanonicalHostedZoneNameID desc) pu)
      (pif (:Scheme fields) (.getScheme desc) pu)
      (pif (:Azs fields) (seq (.getAvailabilityZones desc)) pu)
      (pif (:Subnets fields) (or (seq (.getSubnets desc)) "<noSubnets>") pu)
      (pif (:Sgs fields) (or (seq (.getSecurityGroups desc)) "<noSGs>") pu)
      (pif (:SourceSg fields) (.getGroupName (.getSourceSecurityGroup desc)) pu)
      (pif (:Ctime fields) (str (.getCreatedTime desc)) pu)
      (println)
      (when (:Backends fields)
        (doseq [bsd (seq (.getBackendServerDescriptions desc))]
          (cl-format true "~2@TBackend Server: Port ~d, Policy Names: ~s~%"
                     (.getInstancePort bsd) (.getPolicyNames bsd))))
      (when (:Listeners fields)
        (doseq [listener (map #(.getListener %) (.getListenerDescriptions desc))]
          (cl-format true "~2@TListener: Instance Port ~d, Instance Protocol ~a, ELB Port ~d, ELB Protocl ~a, SSL Cert: ~a~%"
                     (.getInstancePort listener)
                     (.getInstanceProtocol listener)
                     (.getLoadBalancerPort listener)
                     (.getProtocol listener)
                     (.getSSLCertificateId listener))))
      (when (:Policies fields)
        ;; Not sure this is working...
        (let [policies (.getPolicies desc)]
          (cl-format true "~2@TAppCookieStickinessPolicies:~%~{~4@T~s~^~%~}"
                     (map (fn [p] [(.getCookieName p) (.getPolicyName p)]) (.getAppCookieStickinessPolicies policies)))
          (cl-format true "~2@TLBCookieStickinessPolicies:~%~{~4@T~s~^~%~}"
                     (map #(.getPolicyName %) (.getLBCookieStickinessPolicies policies)))
          (cl-format true "~2@TOther Policies: ~s~%" (seq (.getOtherPolicies policies)))))
      ;; These are just instance stubs, not the same as .ec2.model.Instance
      (when-let [instances (and (:Instances fields)
                               (better-not-empty? (seq (.getInstances desc))))]
        (cl-format true "~2@TInstances: ~a~%" (map #(.getInstanceId %) instances))))))
        

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


(defn report-key-pairs
  []
  (doseq [keyPairInfo (.getKeyPairs (.describeKeyPairs (ec2)))]
    (println (.getKeyName keyPairInfo)
             (.getKeyFingerprint keyPairInfo))))


;;;
;;; Cloudwatch
;;;

(defn ^AmazonCloudWatchClient cw
  "Return an AmazonCloudWatchClient instance ready for calls for a single (optional) region.
   'region' is a keyword defaulting to *region*."
  ([] (cw *region*))
  ([region]
     (let [cw (AmazonCloudWatchClient. (make-aws-creds))
           region (if (instance? Region region) region (get-valid region-map region))]
       (.setRegion cw region)
       cw)))

;; (take 125 (describe-alarms-nonlazy)) - verify # batches fetched
(defn- get-alarms-nonlazy
  "Fetch all alarms in paged fashion, as a non-lazy sequence.
   'cw' is an AmazonCloudWatchClient instance."
  [cw]
  (let [alarm-result (.describeAlarms cw (doto (DescribeAlarmsRequest.)
                                          (.setMaxRecords (int 100))))];defaults to 50
    (loop [result (.getMetricAlarms alarm-result) nt (.getNextToken alarm-result)]
      ;;(println "nt=" (str "'" nt "'") "cnt=" (count result))
      (if (and nt (> (count nt) 0))
        (let [alarm-result (.describeAlarms
                            cw (doto (DescribeAlarmsRequest.)
                                 (.setMaxRecords (int 100))
                                 (.setNextToken nt)))]
          (recur (concat result (.getMetricAlarms alarm-result))
                 (.getNextToken alarm-result)))
        result))))
                                                    
;; (take 125 (describe-alarms-lazy)), verify # batches fetched
(defn- get-alarms-lazy
  "Fetch all alarms in paged fashion, as a lazy sequence.
   'cw' is an AmazonCloudWatchClient instance.
   'result' is the seq of MetricAlarms gathered so far.
   'nt' is the nextToken to fetch."
  [cw result nt]
  ;;(println "nt=" (str "'" nt "'") "cnt=" (count result))
  (if (and nt (> (count nt) 0))
    (concat result
            (lazy-seq 
             (let [alarm-result (.describeAlarms
                                 cw (doto (DescribeAlarmsRequest.)
                                      (.setMaxRecords (int 100))
                                      (.setNextToken nt)))]
               (get-alarms-lazy cw (.getMetricAlarms alarm-result)
                                (.getNextToken alarm-result)))))
    result))

(defn describe-alarms-nonlazy
  "Retrieve a non-lazy sequence of zero or more MetricAlarm instances.
   i.e. (take 10 (describe-alarms-nonlazy)) will still fetch all alarms."
  []
  (get-alarms-nonlazy (cw)))

(defn describe-alarms-lazy
  "Retrieve a lazy sequence of zero or more MetricAlarm instances.
   i.e. (take 10 (describe-alarms-nonlazy)) will NOT fetch all alarms, just the first
   'batch' (whose size may wish to optimize but is limited to 100 max)."
  []
  (let [cw (cw)
        alarm-result (.describeAlarms cw (doto (DescribeAlarmsRequest.)
                                           (.setMaxRecords (int 100))))]; defaults to 50
    (get-alarms-lazy cw (.getMetricAlarms alarm-result) (.getNextToken alarm-result))))

(defn report-alarms
  "Report on zero or more MetricAlarm instances, fetch them if none are specified as with 'describe-alarms'.
  :instances A collectionof MetricAlarm instances, optional."
  [& {:keys [instances]}]
  ;; Note: non-lazy took 17.4 secs, lazy took 18.3 secs, for 1761 alarms
  ;; in 50 record batches (the default).  Could be normal statistical/network variance.
  ;; With 100 record batches: non-lazy 14.47 secs, lazy 14.74 secs
  (let [instances (or instances (describe-alarms-nonlazy))]
    (doseq [ma instances]               ;ma == metricAlarm
      (println (.getAlarmName ma)
               (.getMetricName ma)
               (.getAlarmDescription ma)))))
      

  
  
