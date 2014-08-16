(ns jaws.native
  (:use clojure.repl)
  (:use clojure.set)
  (:use [jdt core cl shell])
  (:use [jdt.easyfs :exclude [copy]])
  (:use [clojure.java.io])
  (:use [clojure.pprint :only [cl-format]])
  (:import [com.amazonaws AmazonServiceException])
  (:import [com.amazonaws.auth BasicAWSCredentials])
  (:import [com.amazonaws.regions Regions Region])
  (:import [com.amazonaws.services.autoscaling AmazonAutoScalingClient])
  (:import [com.amazonaws.services.cloudwatch AmazonCloudWatchClient])
  (:import [com.amazonaws.services.cloudwatch.model
            DescribeAlarmsRequest ListMetricsRequest])
  (:import [com.amazonaws.services.ec2 AmazonEC2Client AmazonEC2])
  (:import [com.amazonaws.services.ec2.model
            GetConsoleOutputRequest CreateImageRequest CreateTagsRequest
            DeleteSnapshotRequest DeleteTagsRequest DeregisterImageRequest
            DescribeImagesRequest DescribeInstancesRequest DescribeInstancesResult 
            DescribeInstanceStatusRequest
            DescribeKeyPairsRequest DescribeSecurityGroupsRequest
            DescribeSnapshotsRequest DescribeSubnetsRequest DescribeTagsRequest
            DescribeVolumesRequest DescribeVpcsRequest
            Filter Instance InstanceAttributeName Image
            LaunchPermissionModifications LaunchPermission
            ModifyImageAttributeRequest ModifyInstanceAttributeRequest RunInstancesRequest
            Snapshot
            StartInstancesRequest StopInstancesRequest Tag TerminateInstancesRequest
            Volume])
  (:import [com.amazonaws.services.elasticloadbalancing AmazonElasticLoadBalancingClient])
  (:import [com.amazonaws.services.elasticloadbalancing.model DescribeLoadBalancersRequest])
  (:import [com.amazonaws.services.identitymanagement AmazonIdentityManagementClient])
  (:import [com.amazonaws.services.identitymanagement.model
            GetInstanceProfileRequest GetRolePolicyRequest GetRoleRequest
            ListRolePoliciesRequest])
  (:import java.io.File))

(load "creds")

;;;
;;; Conventions in this module.
;;;
;;; Functions named 'describe-*' or 'list-*' are named after AWS methods.
;;; Functions named 'report-*' are things that use 'describe-*' results to print reports on AWS entities.
;;; Most report functions default to one-line-per-entity formats unless other options are specified.
;;;
;;; Unless an identifier says "*-id" then the object in question is probably an AWS entity, not an entity id.
;;; I.e. 'instance' will be an Instance object, not an instance id.  Usually the documentation will clarify
;;; questions on the formal parameters, if there are any.
;;;

(defonce
  ^{:doc "region keyword to Regions enum mapping"}
  region-map
  (into {}
        (map (fn [region-enum]
               [(keyword (.getName region-enum))
                (Region/getRegion region-enum)])
             (seq (Regions/values)))))

(def valid-regions "Valid values for *region*" (into #{} (keys region-map)))

(defonce
  ^{:dynamic true
    :doc "Default AWS endpoint (region).  Must be one of 'valid-regions'."}
  *region* :us-east-1)

(defn set-region!
  "Call alter-var-root on *region* to change the default region for the calling thread.
   Region value must be one of 'valid-regions'."
  [region]
  {:pre [(valid-regions region)]}
  (alter-var-root #'*region* (constantly region)))

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
;;; AWS identifers based on string content
;;;

(defn instance-id?
  "Return a string representing the instance id of the
   keyword or string identifier, nil otherwise.
   E.g. (instance-id? :i-50131f00) => \"i-50131f00\""
  [id]
  (re-matches #"i-\p{XDigit}{8}" (name id)))

(defn security-group-id?
  "Return a string representing the security group id of the
   keyword or string identifier, nil otherwise."
  [id]
  (re-matches #"sg-\p{XDigit}{8}" (name id)))

(defn snapshot-id?
  "Return a string representing the snapshot id of the
   keyword or string identifier, nil otherwise."
  [id]
  (re-matches #"snap-\p{XDigit}{8}" (name id)))

(defn ami-id?
  "Return a string representing the AMI id of the
   keyword or string identifier, nil otherwise."
  [id]
  (re-matches #"ami-\p{XDigit}{8}" (name id)))

(defn volume-id?
  "Return a string representing the AMI id of the
   keyword or string identifier, nil otherwise."
  [id]
  (re-matches #"vol-\p{XDigit}{8}" (name id)))


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

(defn security-group-id-exists?
  "Return true if the specified security group id exists, false if it does not."
  [group-id]
  ;; Throws if the group does not exist.
  (try 
    (let [result (.describeSecurityGroups(ec2)
                                          (doto (DescribeSecurityGroupsRequest.)
                                            (.setGroupIds [group-id])))]
      (>= (count (.getSecurityGroups result)) 1))
    true
    (catch Exception e false)))

(defn security-group-name-exists?
  "Return true if the specified security group name exists, false if it does not."
  [group-name]
  ;; Throws if the group does not exist.
  (try 
    (let [result (.describeSecurityGroups (ec2)
                                          (doto (DescribeSecurityGroupsRequest.)
                                            (.setGroupNames [group-name])))]
      (>= (count (.getSecurityGroups result)) 1))
    true
    (catch Exception e false)))

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

(defn get-name-tag
  "Return the tag value of a 'Name' tag from a sequence of Tag objects, or nil
   if there isn't a Name tag in the sequence."
  [tag-list]
  (if-let [name-tag (find-if (fn [tag] (= (.getKey tag) "Name")) tag-list)]
    (.getValue name-tag)))

(defn- squish-tags
  "Take a list of tags and compress them into a single vector of strings of the form 'key=val'.
   E.g. [Name=this is a tag description, ...]

   Note that the result of this function is better printed with 'pr' or 'prn'
   rather than 'print' or 'println' so that strings are quoted."
  [tag-list]
  (mapv (fn [tag] (str (.getKey tag) "=" (.getValue tag)))
        (sort-aws-tags tag-list ["Name" "aws:autoscaling:groupName"])))

(defn- describe-tags-lazy
  "Helper routine to fetch tags in paged fashion as a lazy sequence.
   'ec2' is the AmazonEC2Client.
   'result' is the seq of Tags so gathered so far.
   'request' is the DescribeTagsRequest.
   'nextToken' is the next token to fetch."
  [ec2 result request nextToken]
  #_(println "**DEBUG** describe-tags-lazy: nextToken="
           (str "'" nextToken "'") "count=" (count result))
  (if (and nextToken (> (count nextToken) 0)) ; nonempty string
    (concat result
            (lazy-seq
             (let [describeTagsResult
                   (.describeTags ec2
                                  (doto request (.setNextToken nextToken)))]
               (describe-tags-lazy ec2 (.getTags describeTagsResult)
                                   (.getNextToken describeTagsResult)))))
    result))

(defn describe-tags
  "Retrieve Tags known to the account as a lazy sequence.

   Optionally filter for resource ids, tag keys, values, or entity resource types.
   Any option may be a singleton or a seq/collection of strings or keywords.

   Valid resource types: (customer-gateway | dhcp-options | image | instance |
   internet-gateway | network-acl | network-interface | reserved-instances |
   route-table | security-group | snapshot | spot-instances-request | subnet |
   volume | vpc | vpn-connection | vpn-gateway).

   e.g. (describe-tags :resource-ids \"i-50131f00\")

   Note: WILDCARDS, escape with \\
     '*' matches zero or more chars.
     '?' matches exactly one char.

   Note: searches are case sensitive.

   Returns a list of Tag objects."
  [& {:keys [resource-ids keys values resource-types]}]
  (let [request (DescribeTagsRequest.)
        filters (filter identity
                   [
                    (if resource-ids
                      (Filter. "resource-id" (map #(name %) (listify resource-ids))))
                    (if keys
                      (Filter. "key" (map #(name %) (listify keys))))
                    (if values
                      (Filter. "value" (map #(name %) (listify values))))
                    (if resource-types
                      (Filter. "resource-type" (map #(name %) (listify resource-types))))
                    ])]
    (if filters
      (.setFilters request filters))
    (let [ec2 (ec2)
          describeTagsResult (.describeTags ec2 request)]
      (describe-tags-lazy ec2 (.getTags describeTagsResult) request
                          (.getNextToken describeTagsResult)))))

(defn report-tags
  "Print tag information for TagDesciption objects retrieved via describe-tags.
   See describe-tags."
  [tag-descriptions]
  (doseq [tag-description tag-descriptions]
    (print (.getResourceId tag-description)
           (.getResourceType tag-description))
    (print " ")
    (prn (.getKey tag-description)
         (.getValue tag-description))))
  
(defn create-tags
  "Create tags for any specific EC2 entity that can have tags.
   Specify the entity ID (or list of entity IDs) and a map of tag key/value pairs.
   Strings and vals are assumed strings, however keywords are acceptable
   in which case their names will be used.
   If verbose is true, print a message about the tags being assigned to the entity.

   Restrictions:
     Keys limited to 127 unicode chars, case sensitive, cannot start withy 'aws:'
     Values limited to 255 unicode chars, case sensitive.

   Returns nil."
  [entity tag-map & {:keys [verbose]}]
  {:pre [(map? tag-map)]}
  ;; Note: Could probably eliminate 'strify' in favor of 'name'
  (let [strify (fn [x] (if (keyword? x) (name x) (str x)))
        tags (map (fn [e] (Tag. (strify (key e)) (strify (val e)))) tag-map)]
    (when verbose
      (print "Tagging" entity "with ")
      (prn (squish-tags tags)))
    (.createTags (ec2) (CreateTagsRequest. (map name (listify entity)) tags))))

(defn delete-tags
  "Delete specific tags for specific EC2 entity or entities that can have tags.
   Specify the entity ID (or list of entity IDs) and a collection of tag name strings or keywords.
   If verbose is true, print a message about the tags being deleted from the entity.
   Returns nil."
  ;; Note, this function doesn't presently allow you to delete based on tag values,
  ;; but DeleteTagsRequest will allow that.
  [entities tags & {:keys [verbose]}]
  (let [tags (map #(Tag. %) (map name (listify tags)))
        entities (map name (listify entities))]
    (when verbose
      (println "Removing tags" tags "from" entities))
    (.deleteTags (ec2) (doto (DeleteTagsRequest. entities)
                         (.setTags tags)))))
                         

;;;
;;; EC2 - Filter construction
;;;

(defn make-ec2-filter
  "Make and return an ec2.model.Filter given a key and value.
   If key-map is specified, it must be a map
   that is used to convert one key to another before placing it in the filter,
   typically used to conver valid clojure keywords to keyword strings that aren't
   valid as clojure keywords, but are valid as ec2 model Filters.

   E.g. (make-ec2-filter :state :ready #{:state \"state.status\"})
        => #<Filter>(\"state.status\", \"ready\")
   The key-map can also specify other keywords as values, it doesn't have to be a string,
   though it's more efficient that way."
  [k v & [key-map]]
  (let [k (or (and key-map (get key-map k)) k)]
    (Filter. (cond (keyword? k) (name k)
                   (string? k) k
                   :else (throw (Exception.
                                 (str "key " k " of type " (type k)
                                      " cannot be converted to a Filter key."))))
             [(cond (keyword? v) (name v)
                    (integer? v) (int v)
                    :else v)])))

(defn- map->ec2-filters
  "Given a map convert keys and values to Filter elements,
   return a collection of ec2.mode.Filters
   for use with setFilters(Collection<Filter>) on some ec2 model request.
   If 'key-map' is specified, translate keys in 'm' before converting them to
   Filter keys."
  [m & [key-map]]
  {:pre [(map? m)]}
  (into '() (map (fn [e] (make-ec2-filter (key e) (val e) key-map)) (seq m))))


;;;
;;; EC2 - instance status
;;;

(def instance-state-code-map "Map of InstanceState codes to keywords"
  {0 :pending, 16 :running, 32 :shutting-down, 48 :terminated, 64 :stopping, 80 :stopped})
(def instance-statuses "Valid instance status values"
  #{:ok :impaired :initializing :insufficient-data :not-applicable})
(def instance-reachabilities "Valid instance reachability values"
  #{:passed :failed :initializing :insufficient-data})

(def describe-instance-status-filter-map
  "Map filter keys for describe-instance-status to valid Filter names for the request."
  {:az "availability-zone"
   :event-code "event.code"
   :event-description "event.description"
   :event-not-after "event.not-after"
   :event-not-before "event.not-before"
   :instance-state "instance-state-name"
   :instance-reachability "instance-status.reachability"
   :instance-status "instance-status.status"
   :system-reachability "system-status.reachability"
   :system-status "system-status.status"
   })
   
(defn describe-instance-status
  "Return a sequence of InstanceStatus objects for EC2 instances.
  :ids - instance ids (or collection thereof) to describe, default nil (all instances).
  :all - if true include status for instances in states other than running.
  :filters - map of attributes/values to filter on. Keys:
           :az - availability zone of the instance
           :event-code - instance-{reboot,retirement,stop}, system-{reboot,maintenance}
           :event-description - event description
           :event-not-after - latest end time for the scheduled event
           :event-not-before - earliest start time for the scheduled event
           :instance-state-code - key from instance-state-code-maap (e.g. 0)
           :instance-state - one of the values in instance-state-code-map (e.g. :pending)
           :instance-reachability - one of 'instance-reachabilities'
           :instance-status:  - one of 'instance-statuses'
           :system-reachability - one of 'instance-rechabilities'
           :system-status - one of 'instance-statuses'"
  [& {:keys [ids all filters]}]
  (let [request (DescribeInstanceStatusRequest.)]
    (if ids (.setInstanceIds request (listify ids)))
    (if all (.setIncludeAllInstances request true))
    (if filters
      (.setFilters request (map->ec2-filters filters describe-instance-status-filter-map)))
    (let [result (.describeInstanceStatus (ec2) request)]
      (if (.getNextToken result)
        (println "*FINISH*: pagination for missing entries in DescribeInstanceStatus"))
      (.getInstanceStatuses result))))

(defn report-instance-status
  "Report details of InstanceStatus objects.
   If no instance-statuses are specified, retrieve them as with describe-instance-status."
  [& [instance-statuses]]
  (let [instance-statuses (or instance-statuses (describe-instance-status))]
    (doseq [status instance-statuses]
      (println (.getInstanceId status)
               (.getName (.getInstanceState status))
               (.getAvailabilityZone status))
      (doseq [event (.getEvents status)]
        (println "  Events:")
        (println "   " (.getCode event)
                 (.getDescription event)
                 "Not After:" (.getNotAfter event)
                 "Not Before:" (.getNotBefore event)))
      (let [i-status (.getInstanceStatus status)
            s-status (.getSystemStatus status)
            detail-fn (fn [details]
                        (doseq [detail details]
                          (println "   " (.getName detail) (.getStatus detail)
                                   "impaired since:" (str (.getImpairedSince detail)))))]
        (println "  Instance status: " (.getStatus i-status))
        (detail-fn (.getDetails i-status))
        (println "  System status: " (.getStatus s-status))
        (detail-fn (.getDetails s-status))))))

(defn report-problem-instances
  "Wrapper around report-instance-status + describe-instance-status and some filters
   to find instances we can't reach or that are otherwise known to have problems."
  []
  (let [instances
        (into #{}                       ;filters duplicates
              (concat (describe-instance-status :filters {:instance-reachability :failed})
                      (describe-instance-status :filters {:system-reachability :failed})
                      (describe-instance-status :filters {:instance-status :impaired})
                      (describe-instance-status :filters {:system-status :impaired})))]
    (report-instance-status instances)))


;;;
;;; EC2 - instance queries
;;;
(defn get-instance
  "Retrieve Instance given ID or nil if the Instance doesn't exist.
   Id may be string or keyword."
  [instance-id]
  ;; AmazonServiceException 400 if the entity doesn't exist.
  (try
    (first (.getInstances
            (first (.getReservations
                    (.describeInstances (ec2) (doto (DescribeInstancesRequest.)
                                                (.setInstanceIds [(name instance-id)])))))))
    (catch AmazonServiceException e nil)))


(defmulti  instance-state
    "Retrieve instance state for an EC2 instance as a keyword, e.g. :running.
     Note that an instance-id will cause a refetch of state, while an Instance
     object merely decodes the state already in memory (which will not change
     across successfive calls)."
    class)
(defmethod instance-state String [instance-id]
  (instance-state (get-instance instance-id)))
(defmethod instance-state Instance [instance]
  (let [code (.getCode (.getState instance))
        state (get instance-state-code-map code :unknown-state-code)]
    (if (= state :unknown-state-code)
      (do (comment (println "Oops: getState=" (.getState instance)));commented out for demo mode.
          (str state "-" code))
      state)))

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
  
(defmulti  instance-id
  "Retrieve the instance id of an instance (or, if the argument is already an ID, return the identity."
  class)
(defmethod instance-id String [instance-id] instance-id)
(defmethod instance-id clojure.lang.Keyword [instance-id] (name instance-id))
(defmethod instance-id Instance [instance] (.getInstanceId instance))

(defmulti  instance-public-dns-name
  "Retrieve the public dns name for an instance or instance id,
   return nil if there isn't one.  Note that this information isn't available at all
   until the instance is in the :running state, and maybe not even then for VPC instances."
  class)
(defmethod instance-public-dns-name String [instance-id]
  (instance-public-dns-name (get-instance instance-id)))
(defmethod instance-public-dns-name Instance [instance]
  (let [dns-name (.getPublicDnsName instance)]
    (and (> (count dns-name) 0)
         dns-name)))

(defmulti  instance-public-ip-address
  "Retrieve the public IP address for an instance or instance id,
   return nil if there isn't one."
  class)
(defmethod instance-public-ip-address String [instance-id]
  (instance-public-ip-address (get-instance instance-id)))
(defmethod instance-public-ip-address Instance [instance]
  (let [ip-address (.getPublicIpAddress instance)]
    (and (> (count ip-address) 0)
         ip-address)))

(defn instance-volume-ids
  "Return a collection of ebs volume IDs attached to an Instance object."
  [instance]
  (->> (.getBlockDeviceMappings instance)
       (map (fn [mapping] (.getEbs mapping)))
       (map (fn [dev] (.getVolumeId dev)))))

(defn instance-availability-zone
  "Return the availability zone of an Instance"
  [instance]
  (.getAvailabilityZone (.getPlacement instance)))

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

(def describe-instances-filters
  "A map whose keys are valid filter names for describe-instances
   and whose values serve as documentation on the respective keys.
   This was generated based on AWS SDK 1.8.8 and may not reflect the complete
   list of valid filters."
  {:architecture "The instance architecture (i386 | x86_64)."
   :availability-zone "The Availability Zone of the instance."
   :block-device-mapping.attach-time
   "The attach time for an Amazon EBS volume mapped to the instance."
   :block-device-mapping.delete-on-termination
   "A Boolean that indicates whether the Amazon EBS volume is deleted on
    instance termination."
   :block-device-mapping.device-name
   "The device name for the Amazon EBS volume (for example, /dev/sdh)."
   :block-device-mapping.status
   "The status for the Amazon EBS volume (attaching | attached | detaching | detached)."
   :block-device-mapping.volume-id "The volume ID of the Amazon EBS volume."
   :client-token "The idempotency token you provided when you launched the instance."
   :dns-name "The public DNS name of the instance."
   :group-id
   "The ID of the security group for the instance. If the instance is in
    EC2-Classic or a default VPC, you can use group-name instead."
   :group-name
   "The name of the security group for the instance. If the instance is in a
    nondefault VPC, you must use group-id instead."
   :hypervisor "The hypervisor type of the instance (ovm | xen)."
   :iam-instance-profile.arn
   "The instance profile associated with the instance. Specified as an ARN."
   :image-id "The ID of the image used to launch the instance."
   :instance-id "The ID of the instance."
   :instance-lifecycle "Indicates whether this is a Spot Instance (spot)."
   :instance-state-code
   "The state of the instance, as a 16-bit unsigned integer. The high byte is
    an opaque internal value and should be ignored. The low byte is set based
    on the state represented. The valid values are: 0 (pending), 16 (running),
    32 (shutting-down), 48 (terminated), 64 (stopping), and 80 (stopped)."
   :instance-state-name
   "The state of the instance
    (pending | running | shutting-down | terminated | stopping | stopped)."
   :instance-type "The type of instance (for example, m1.small)."
   :instance.group-id
   "The ID of the security group for the instance. If the instance is in
    EC2-Classic or a default VPC, you can use instance.group-name instead."
   :instance.group-name
   "The name of the security group for the instance. If the instance is in a
    nondefault VPC, you must use instance.group-id instead."
   :ip-address "The public IP address of the instance."
   :kernel-id "The kernel ID."
   :key-name "The name of the key pair used when the instance was launched."
   :launch-index
   "When launching multiple instances, this is the index for the instance in
    the launch group (for example, 0, 1, 2, and so on)."
   :launch-time "The time when the instance was launched."
   :monitoring-state "whether instance monitoring is enabled (disabled | enabled)."
   :owner-id "The AWS account ID of the instance owner."
   :placement-group-name "The name of the placement group for the instance."
   :platform "The platform. Use windows if you have Windows instances otherwise leave blank."
   :private-dns-name "The private DNS name of the instance."
   :private-ip-address "The private IP address of the instance."
   :product-code "The product code associated with the AMI used to launch the instance."
   :product-code.type "The type of product code (devpay | marketplace)."
   :ramdisk-id "The RAM disk ID."
   :reason
   "The reason for the current state of the instance (for example,
    shows \"User Initiated [date]\" when you stop or terminate the instance).
    Similar to the state-reason-code filter."
   :requester-id
   "The ID of the entity that launched the instance on your behalf (for example,
    AWS Management Console, Auto Scaling, and so on)."
   :reservation-id "The ID of the instance's reservation."
   :root-device-name "Name of instance root device (for example, /dev/sda1)."
   :root-device-type "Type of instance root device (ebs | instance-store)."
   :source-dest-check
   "Indicates whether the instance performs source/destination checking. A value
    of true means that checking is enabled, and false means checking is disabled.
    The value must be false for the instance to perform network address translation
    (NAT) in your VPC."
   :spot-instance-request-id "The ID of the Spot Instance request."
   :state-reason-code "The reason code for the state change."
   :state-reason-message "A message that describes the state change."
   :subnet-id "The ID of the subnet for the instance."
   :tag:key=value
   "The key/value combination of a tag assigned to the resource,
    where tag:key is the tag's key.  This filter key is poorly documented.
    Actual usage example for Creator=dtenny k/v tag: {:tag:Creator \"dtenny\"}"
   :tag-key
   "The key of a tag assigned to the resource. This filter is independent of the
    tag-value filter. For example, if you use both the filter \"tag-key=Purpose\"
    and the filter \"tag-value=X\", you get any resources assigned both the tag
    key Purpose (regardless of what the tag's value is), and the tag value X
    (regardless of what the tag's key is). If you want to list only resources
    where Purpose is X, see the tag:key=value filter."
   :tag-value
   "The value of a tag assigned to the resource. This filter is independent
    of the tag-key filter."
   :tenancy "The tenancy of an instance (dedicated | default)."
   :virtualization-type "The virtualization type of the instance (paravirtual | hvm)."
   :vpc-id "The ID of the VPC that the instance is running in."
   :network-interface.description "The description of the network interface."
   :network-interface.subnet-id "The ID of the subnet for the network interface."
   :network-interface.vpc-id "The ID of the VPC for the network interface."
   :network-interface.network-interface.id "The ID of the network interface."
   :network-interface.owner-id "The ID of the owner of the network interface."
   :network-interface.availability-zone "Availability Zone for the network interface."
   :network-interface.requester-id "The requester ID for the network interface."
   :network-interface.requester-managed "Whether the network interface is managed by AWS."
   :network-interface.status "The status of the network interface (available) | in-use)."
   :network-interface.mac-address "The MAC address of the network interface."
   :network-interface-private-dns-name "The private DNS name of the network interface."
   :network-interface.source-destination-check
   "Whether the network interface performs source/destination checking.
    A value of true means checking is enabled, and false means checking is
    disabled. The value must be false for the network interface to perform
    network address translation (NAT) in your VPC."
   :network-interface.group-id "Security group ID associated with the network interface."
   :network-interface.group-name "Security group name associated with the network interface."
   :network-interface.attachment.attachment-id "The ID of the interface attachment."
   :network-interface.attachment.instance-id
   "Instance ID to which the network interface is attached."
   :network-interface.attachment.instance-owner-id
   "The owner ID of the instance to which the network interface is attached."
   :network-interface.addresses.private-ip-address
   "The private IP address associated with the network interface."
   :network-interface.attachment.device-index
   "The device index to which the network interface is attached."
   :network-interface.attachment.status
   "The status of the attachment (attaching | attached | detaching | detached)."
   :network-interface.attachment.attach-time
   "The time that the network interface was attached to an instance."
   :network-interface.attachment.delete-on-termination
   "Specifies whether the attachment is deleted when an instance is terminated."
   :network-interface.addresses.primary
   "Specifies whether the IP address of the network interface is the
    primary private IP address."
   :network-interface.addresses.association.public-ip
   "The ID of the association of an Elastic IP address with a network interface."
   :network-interface.addresses.association.ip-owner-id
   "The owner ID of the private IP address associated with the network interface."
   :association.public-ip "Elastic IP address bound to the network interface."
   :association.ip-owner-id
   "The owner of the Elastic IP address associated with the network interface."
   :association.allocation-id
   "The allocation ID returned when you allocated the Elastic IP address
    for your network interface."
   :association.association-id
   "The association ID returned when the network interface was associated
    with an IP address."
   })

(defn describe-instances-filters-key? [keyword]
  "Given a keyword intended to match a keyword in the 'describe-instances-filters' map
   return true if it is a valid keyword in the map, or nil otherwise, with special
   treatment for the :tag:<key>=<value> syntax that is not literally matched."
  (let [s (name keyword)]
    (if (.startsWith s "tag:")
      true
      (get describe-instances-filters keyword))))

(defn describeInstancesResult->instances
  "Convert DescribeInsancesResult objects to a sequence of instances.
   The argument may be a singleton DescribeInstancesResult or a collection of them."
  [results]
  (->> (seqify results)
       flatten
       (map (fn [describeInstancesResult]
              (seq (.getReservations describeInstancesResult))))
       ;; Sometimes there are no reservations ina DescribeInstancesResult (get null)
       ;; E.g. on filtered requests.
       (filter identity)
       flatten
       (map (fn [reservation] (seq (.getInstances reservation))))
       flatten))

(defn old-describe-instances
  "Retrieve zero or more Instances with various filters and regions applied.
   Returns a collection that can be fed as :data to 'report-instances', e.g.
   (report-instances :instances (old-describe-instances :tag-regex #\"(?i)created\"))
   Options:
   :region a region keyword from 'region-map', or :all to operate on all regions.
   :ids a string or keyword instance ID, or collection/sequence of same, specifying specific instances
        whose data should be retrieved.
   :tag-regex a regular expression (java.util.regex.Pattern) applied to tag names and
              values as a filter.  Instances lacking the regex will not be returned.
              Instances are only returned if the regex passes a 'find', not a
              'matches' operation. '(?i)' may be useful in your regex to ignore case.
              Note that tag regexes must filter tags after retrieval from amazon."
  [& {:keys [region tag-regex ids]}]
  (print "**WARNING** Deprecated: old-describe-instances")
  (let [regions (regions-for-key region)
        fetch-fn (if ids
                   (let [ids (map name (listify ids))]
                     (if (> (count ids) 0)
                       (fn [region] (.describeInstances (ec2 region)
                                                        (doto (DescribeInstancesRequest.)
                                                          (.setInstanceIds ids))))
                       (constantly nil)))
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

;; jdt.core candidate
;;; See also test-validate-defn-keywords in native_test.clj
(defn validate-defn-keywords
  "Given a map of keyword/value pairs specify to a function call to a function
   declared with a map, e.g. (defn foo [& {:keys [a b c] :as all-keys}])

   Throw IllegalArgumentException if any keywords in
   all-keys aren't in the parameters named by valid-keys.

   This function is useful because functions declared like 'foo' above
   will accept other keywords without complaint.

   This function is NOT efficient, it conses up a lot of crap because it's flexible
   on the arguments it takes.  If we simplified the calling assumptions we could
   make it much more efficient.  For now it's meant to be convenient to use, typically
   for those functions that are used frequently in interactiev REPL contexts where
   typos or otherwise incorrect keyword names are common.

   'all-keys-map' is the :as parameter name for keywords in a 'defn'.

   'valid-keys' keywords (or symbols or strings that will be coerced to keywords)
   or collections of same representing valid keywords. 

   Any key in all-keys-map that isn't in valid-keys will trigger an exception.

   Example based on the above 'foo' declaration in docstring,
   the following are all equivalent validators for arguments passed to foo:
 
       (validate-defn-keywords all-keys :a :b :c)
       (validate-defn-keywords all-keys '[a b c])
       (validate-defn-keywords all-keys {:a 1 :b 2 :c 3})
       (validate-defn-keywords all-keys {:a 1 :b 2} :c)
   "
  [all-keys-map & valid-keys]
  (let [make-key (fn [x] (if (keyword? x) x (keyword (name x))))
        plain-keys (into [] (map make-key (filter #(not (coll? %)) valid-keys)))
        collections-of-keys
        (into [] 
          (map (fn [c]
                 (if (map? c)
                   (into #{} (map make-key (keys c)))
                   (into #{} (map make-key (seq c)))))
               (filter #(coll? %) valid-keys)))]
    (doseq [e all-keys-map]
      (let [k (key e)]
        (if-not (or (some #(= k %) plain-keys)
                    (some #(contains? % k) collections-of-keys))
          (throw (IllegalArgumentException.
                  (str "Keyword " k " is not a valid parameter in the calling function."
                       "\nValid keys are: "
                       ;; map seq because flatten doesn't so sets/maps
                       (pr-str
                        (flatten (conj (map seq collections-of-keys) plain-keys)))))))))))

(defn- describe-instances-lazy
  "Helper routine for lazy paged fetch support for describe-instances.
   'ec2' is the AmazonEC2Client.
   'result' is the seq of Instances so gathered so far.
   'request' is the DescribeInstancesRequest.
   'nextToken' is the next token to fetch.
   'post-filter-fn' is a function that filters the 'result' seq.
   It can be nil if there is no filtering to be done."
  [ec2 result request nextToken post-filter-fn]
  #_(println "**DEBUG** describe-tags-lazy: nextToken="
           (str "'" nextToken "'") "count=" (count result))
  (if (and nextToken (> (count nextToken) 0)) ; nonempty string
    (concat result
            (lazy-seq
             (let [describeInstancesResult
                   (.describeInstances
                    ec2 (doto request (.setNextToken nextToken)))]
               (describe-instances-lazy
                ec2  (describeInstancesResult->instances describeInstancesResult)
                request (.getNextToken describeInstancesResult) post-filter-fn))))
    (if post-filter-fn
      (filter post-filter-fn result)
      result)))

(defn describe-instances
  "Return a sequence of Instance objects, typically useful in conjunction with
   'report-instances' via the :instances argument to that function.

   Note that this function differs from the SDK API in that you can't specify
   multiple Filter objects for the same key, if that's a problem you may need
   to use the API directly.

   Options:

   :ids - An instance id or seq of instance ids.

   :help - Print out the list of valid filters if true, and ignore other arguments.

   :filters
      A Map of attribute names or values to filter on.
      Attribute names (keys) can be keywords or strings (assume case sensitive).
      Attribute values can take on a wider set of types.  Any Keyword values
      are converted to strings on the keyword name.
      A single key/attribute-name can have multiple values.

      Note that filter names and values can use the wildcards '*' (zero or more chars)
      and '?' (zero or one char), and should escape those characers with a backslash
      otherwise.  Filter matches are case sensitive in the SDK API
      (unlike the AWS web console).

      Filter examples:

        :filters {:instance-id :i-333249ff}  (you could juse use :ids for this)
        :filters {:instance-id [:i-333249ff \"i-3339ab33\"]}
        :filters {:tag-value \"dtenny\"}
        :filters {:key-name \"dtenny*\"}

      And now for a tricky example because it's poorly documented for the supposed
      tag:key=value filter name:

        :filters {:tag:Creator \"dtenny\"}
 
      To find instances with the tag/value combo of Creator=dtenny.

      See 'describe-instances-filters' or use the :help argument
      for a complete list of filters.

   :tag-regex
      A regular expression (java.util.regex.Pattern) applied to tag names and
      values as a post-query filter. Instances lacking the regex will not be returned.
      Instances are only returned if the regex passes a 'find', not a
      'matches' operation. '(?i)' may be useful in your regex to ignore case."

  [& {:keys [ids help filters tag-regex]
      :or   {filters {}}
      :as   all-keys
      }]
  (validate-defn-keywords all-keys '[ids help filters tag-regex])
  (if help
    (doseq [e describe-instances-filters]
      (println (key e))
      (println "   " (val e)))
    (let [tag-regex-fn (if tag-regex (tag-regex-find-fn tag-regex))
          request (DescribeInstancesRequest.)
          keyword (fn [x] (keyword? x) x (keyword x))
          ec2-filters
          (map (fn [e]
                 (let [filter-key (key e)]
                   (if-not (describe-instances-filters-key? (keyword filter-key))
                     (println "**WARNING**: UNKNOWN FILTER:" filter-key))
                   (Filter. (name filter-key)
                            (map (fn [v]
                                   (if (instance? clojure.lang.Named v)
                                     (name v)
                                     v))
                                 (listify (val e))))))
               (seq filters))]

      ;; These two exceptions seem spurious, I don't *always* get them when I set
      ;; max results with the things they complain about
      ;;
      ;; AmazonServiceException The parameter 'maxResults' cannot be used with tag filters in the parameter 'filterSet'. Remove either the tag filters from 'filterSet' or the 'maxResults' parameter and try again. (Service: AmazonEC2; Status Code: 400; Error Code: InvalidParameterCombination; Request ID: c3d1ae82-d8df-45bf-8c52-c8e185a19e9e)  com.amazonaws.http.AmazonHttpClient.handleErrorResponse (AmazonHttpClient.java:937)
      ;; AmazonServiceException The parameter instancesSet cannot be used with the parameter maxResults (Service: AmazonEC2; Status Code: 400; Error Code: InvalidParameterCombination; Request ID: 322fbf3d-5b36-4c21-b03e-f230b5bb6f91)  com.amazonaws.http.AmazonHttpClient.handleErrorResponse (AmazonHttpClient.java:937)
      (if-not (or ids
                  (some (fn [k] (.startsWith k "tag"))
                        (map #(.getName %) ec2-filters)))
        (.setMaxResults request (int 1000))) ; max 1000

      (if ids
        (.setInstanceIds request (map name (listify ids))))
      (if-not (empty? ec2-filters)
        (.setFilters request ec2-filters))
      (let [ec2 (ec2)
            describeInstancesResult (.describeInstances ec2 request)]
        (describe-instances-lazy
         ec2 (describeInstancesResult->instances describeInstancesResult)
         request (.getNextToken describeInstancesResult)
         tag-regex-fn)))))

;; Some stupid report printing functions & macros
(defn- pu "print unquoted/friendly, ie. ~a" [x] (print x) (print " "))
(defn- pq "print quoted/readable, ie. ~s" [x] (pr x) (print " "))
(defmacro pif
  "print val using print-fn if test is true, avoid computing val more than once"
  [test val print-fn]
  `(if ~test
     (let [val# ~val]
       (~print-fn val#))))

;; *TBD*: List valid keywords for fields if an improper one is given, right now we silently ignore it.
;; *TBD*: Consider implicit merging of :instances and :instance-ids as we do in {start,stop,terminate}-instances.
;; and eliminate one or the other of those keywords.
;; *TBD*: consider DescribeInstanceStatus merging with this function, so we can report
;; unreachable systems, etc, on the instance report.
(defn report-instances 
  "Print a information about instances.
   The default is to print one line of information per instance, unless options
   are specified for other details.

   Options:
   :indent all lines with the indicated (minimum) number of leading spaces
           indentation desired (default *indent*).  note that secondary lines (if
           more than one line per instance is printed) are indented an
           additional indent-incr spaces.
   :indent-incr amount to additionally indent secondary data lines (for
                options where more than one line per instance is printed. Default 2.
   :instances An Instance or collection thereof.  If neither this nor :ids
              is speciied, (describe-instances is called to retrieve data.
              If both are specified, the resulting instances from each field are used
              (all together).  Note that you can turn instance IDs to instances
              via 'describe-instances'.
   :ids An instance ID or collection thereof, passed to 'describe-instances'.
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
  [& {:keys [instances ids vpc-mode indent indent-incr fields include exclude split-after]
      :or {indent *indent* indent-incr 2
           fields #{:ImageId :VpcId :SubnetId :PublicDnsName :KeyName :State :InstanceType :SecurityGroups :Tags}
           include #{} exclude #{} }}]
  {:pre [(set? include) (set? exclude) (set? fields)]}
  (let [instances2 (and instances (seqify instances))
        instances2a (and ids (describe-instances :ids ids))
        instances3 (concat instances2 instances2a)
        fields (difference (union fields include) exclude)
        split-after (into #{} (seqify split-after))
        sp (fn [x] (when (split-after x)
                     (println)
                     (do-indent(+ indent indent-incr))))     ;split if necessary
        xpr (fn [key val printfn]         ;print and maybe split, use 'pif' or similar?
              (when (get fields key)
                (printfn val)
                (sp key)))]
    (doseq [instance instances3]
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

;; *TODO*: move to jdt.core
(defn exception-retry
  "Call function f with exception handler fe.  If an
   exception is thrown by f, call fe on the exception, and then call f again
   if the result of calling fe is logically true or unless fe throws.

   If f completes execution without throwing we return the return value of f.
   If f throws and fe returns logical false, return nil.

   f must not return a function, this is prohibited and will result in an exception.

   This function is a non-recursive workaround for situations for where
   you want to recurse in a catch/finally statement (i.e. retry a try block in the face of
   exceptions thrown from the try block).  You can't use 'recur' in catch/finally.
   This works around it.

   E.g. (loop [] (try (f) (catch Exception e (recur)))) ; WILL NOT WORK
   but  (exception-retry f (fn [] true)) ; WILL WORK

   In practice you want fe to examine the exception raised
   and probably sleep before returning to try f again.  Maybe print a message
   that this a retry is happening."
  [f fe]
  (let [tryfn
        (fn [] (try (let [result (f)]
                      (assert (not (fn? result)))
                      result)
                    (catch Exception e (if (fe e) f nil))))]
    (trampoline tryfn)))

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
   :private-ip-address A specific IP address in dotted IPV4 notation to be assigned to the instance
           (vpc instances only).
   :subnet A specific subnet ID for instances started in a VPC.
   :retry-if If specified is a string corresponding to an one of error codes as documented
             in http://docs.aws.amazon.com/AWSEC2/latest/APIReference/api-error-codes.html.
             If an AmazonServiceException is thrown with code 400 and
             AWS Error Code matching the parameter, we will retry the run-instances value.
             Known useful codes: 'InvalidIPAddress.InUse' if you're retrying a specific
             ip address assignment to a recently disassociated EIP or private IP address in a VPC.
   :wait   true if this function should not exit until all instances have started.
           Note that they instances may not yet be responsive just because they're 'running'
           and have a DNS address.  YMMV.
   :region a region keyword from 'region-map' to override *region*."
  [ami-id & {:keys [keyname type group-ids group-names min max private-ip-address subnet
                    retry-if wait region]
             :or {region *region* type "t1.micro" min 1 max 1}}]
  {:pre [(not (= region :all))]}
  (let [min (int min)
        max (int max)
        request (RunInstancesRequest. ami-id min max)]
    (.setInstanceType request type)
    (if keyname (.setKeyName request keyname))
    (if group-ids (.setSecurityGroupIds request (listify group-ids)))
    (if group-names (.setSecurityGroups request (listify group-names)))
    (if private-ip-address (.setPrivateIpAddress request private-ip-address))
    (if subnet (.setSubnetId request subnet))
    (let [run-fn (fn [] (->> (.runInstances (ec2 region) request)
                             (.getReservation)))
          handler-fn (fn [e]   ; return true if we should retry on exception e
                       (if (and retry-if
                                (instance? AmazonServiceException e)
                                (= (.getStatusCode e) 400)
                                (= (.getErrorCode e) retry-if))
                         (do (println e)
                             (println "Retrying the run-instances operation again after a 15 second sleep.")
                             (Thread/sleep 15000)
                             true)      ;true => please retry the run-fn in exception-retry
                         (throw e)))
          reservation (exception-retry run-fn handler-fn)
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
   ids     an  instance or instance ID, or collection/sequence of same,
           specifying specific instances to be started.
   :wait   true if this function should not exit until all instances have started.
           Note that they instances may not yet be responsive just because they're 'running'
           and have a DNS address.  YMMV.
   :region a region keyword from 'region-map' to override *region*."
  [ids & {:keys [region wait]
          :or {region *region*}}]
  {:pre [(not (= region :all))]}
  (let [ids (map instance-id (listify ids))]
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
  "Stop one or more instances, waiting if requested.  Return value unspecified.
   ids     an  instance or instance ID, or collection/sequence of same,
           specifying specific instances to be stopped.
   :wait   true if this function should not exit until all instances have stopped.
   :region a region keyword from 'region-map' to override *region*."
  [ids & {:keys [region wait]
          :or {region *region*}}]
  {:pre [(not (= region :all))]}
  (let [ids (map instance-id (listify ids))]
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

(defn terminate-instances
  "Terminate one or more instances.  Return value unspecified.
   ids     an  instance or instance ID, or collection/sequence of same,
           specifying specific instances to be deleted.
   :region a region keyword from 'region-map' to override *region*.
   :wait   if true, wait until the instance reaches state :terminated.
   :force  if true, ensure that we can disable the instance via termination APIs
           (i.e cancel 'DisableApiTermination' status)."
  [ids & {:keys [region force wait]
          :or {region *region*}}]
  {:pre [(not (= region :all))]}
  (let [ids (map instance-id (listify ids))]
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
               (.getName (.getCurrentState instanceStateChange))))
    (if wait
      (doseq [id ids]
        (wait-for-instance-state id :terminated :verbose true)))))

(defn instance-console-output
  "Retrieve the console output of an instance given an instance ID"
  [instance-id]
  (->> (.getConsoleOutput (ec2) (GetConsoleOutputRequest. instance-id))
       (.getDecodedOutput)))

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

(defn get-security-group
  "Retrieve SecurityGroup given ID or nil if the SecurityGroup doesn't exist.
   ID may be string or keyword."
  [security-group-id]
  ;; AmazonServiceException 400 if the entity doesn't exist.
  ;; DescribeSecurityGroupsRequest introduced in SDK 1.8.7
  (try
    (first (.getSecurityGroups
            (.describeSecurityGroups (ec2) (doto (DescribeSecurityGroupsRequest.)
                                      (.setGroupIds [(name security-group-id)])))))
    (catch AmazonServiceException e nil)))



;;;
;;; EC2 VPC
;;;

(defn print-ip-permission [ip-permission]
  (println "from port" (.getFromPort ip-permission)
           "protocol" (.getIpProtocol ip-permission)
           "ranges" (seq (.getIpRanges ip-permission))
           "to port" (.getToPort ip-permission)
           "id grps" (seq (.getUserIdGroupPairs ip-permission))))

(defn get-vpc
  "Retrieve VPC given ID or nil if the VPC doesn't exist.
   ID may be string or keyword."
  [vpc-id]
  ;; AmazonServiceException 400 if the entity doesn't exist.
  (try
    (first (.getVpcs
            (.describeVpcs (ec2) (doto (DescribeVpcsRequest.)
                                        (.setVpcIds [(name vpc-id)])))))
    (catch AmazonServiceException e nil)))

(defn describe-vpcs
 "Return a list of Vpc objects.
  Options:
    :ids - a vpc id or sequence of vpc ids, if unspecified all vpcs will be listed.
    :filters - map of attributes/values to filter on.  Key (k/v can be keyword, string, or other for vals).
      cidr - The CIDR block of the VPC. The CIDR block you specify must exactly match the VPC's CIDR block for information to be returned for the VPC.
      dhcp-options-id - The ID of a set of DHCP options.
      isDefault - Indicates whether the VPC is the default VPC.
      state - The state of the VPC (pending | available).
      tag:key=value - The key/value combination of a tag assigned to the resource.
      tag-key - The key of a tag assigned to the resource. 
      tag-value - The value of a tag assigned to the resource."
 [& {:keys [ids filters]}]
 (let [request (DescribeVpcsRequest.)]
   (if ids (.setVpcIds request (listify ids)))
   (if filters (.setFilters request (map->ec2-filters filters)))
   (seq (.getVpcs (.describeVpcs (ec2) request)))))

(defn report-vpcs
  "Report on zero or more Vpc instances,
  fetch them if non arespecified as with 'describe-vpcs'.

  Options: 
   :vpcs - a Vpc object, or collection of Vpc objects.
   :ids - a vpc id, or collectio nof vpc ids.
   :fields - set of fields to display in addition to the vpc id.
             Defaults to #{:CidrBlock :IsDefault :State :Tags}.
             Additional fields include: :DhcpOptionsId :InstanceTenancy
   :include - Set of additional fields to display, defaults to #{}.
   :exclude - Set of additional fields to exclude from the display, defauls to #{}.
   :indent indent printed lines with the indicated (minimum) number of leading spaces
           indentation desired (default *indent*).  note that secondary lines (if
           more than one line per instance is printed) are indented an
           additional indent-incr spaces.
   :indent-incr amount to additionally indent secondary data lines (for
                options where more than one line per instance is printed. Default 2.

  Returns nil."
  [& {:keys [vpcs ids fields include exclude indent indent-incr]
      :or {fields #{:CidrBlock :IsDefault :State :Tags} include #{} exclude #{}
           indent *indent* indent-incr 2}}]
  {:pre [(set? include) (set? exclude) (set? fields)]}
  (let [fetched-vpcs (if (or (not vpcs) ids) (describe-vpcs :ids ids))
        vpcs (concat (listify vpcs) fetched-vpcs)
        fields (difference (union fields include) exclude)]
    (doseq [vpc vpcs]
      (do-indent indent)
      (pu (.getVpcId vpc))
      (pif (:CidrBlock fields) (.getCidrBlock vpc) pu)
      (pif (:IsDefault fields) (.getIsDefault vpc) pu)
      (pif (:State fields) (.getState vpc) pu)
      (pif (:DhcpOptionsId fields) (.getDhcpOptionsId vpc) pu)
      (pif (:InstanceTenancy fields) (.getInstanceTenancy vpc) pu)
      (pif (:Tags fields) (squish-tags (.getTags vpc)) pq)
      (println))))

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
                     
(defn vpc-instances
  "Return a (possibly empty) sequence of Instances in the specified VPC."
  [vpc-id]
  (describeInstancesResult->instances 
   (.describeInstances
    (ec2) (doto (DescribeInstancesRequest.)
            (.setFilters [(Filter. "vpc-id" [vpc-id])])))))

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
      (if-let [instances (not-empty? (vpc-instances (.getVpcId vpc)))]
        (binding [*indent* (+ *indent* 4)]
          (report-instances :instances instances
                            :exclude #{:VpcId} :include #{:PrivateIpAddress}))))))

(defn vpc-instance-at-address
  "Return the Instance of an existing EC2 instance assigned the indicated address
   in the indicated VPC, or nil if there is no such instance.

   vpc-id should be a string id similar to 'vpc-b60efed3'.
   ip-address should be a dotted ip V4 address as a string.

   Note that the instance could be in a number of non-terminated states.  We
   don't return an instance if for terminated (but information-available)
   instances.

   Right now this is overly general and could theoretically (but not in practice)
   return a match because a public ip address matched a private ip address, etc.
   So we ought to specify which type of address we're trying to match, but for now
   we don't."
  [vpc-id ip-address]
  {:pre [(string? ip-address)]}
  ;; Terminated instances won't have ip addresses, no need
  ;; for further filtering.
  (find-if (fn [instance]
             (or (= (.getPrivateIpAddress instance) ip-address)
                 (= (.getPublicIpAddress instance) ip-address)))
           (vpc-instances vpc-id)))


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


;; Early Testing
#_
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

;; Early testing
#_
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

(defn get-image
  "Retrieve Image given ID or nil if the Image doesn't exist.
   ID may be string or keyword."
  [image-id]
  ;; AmazonServiceException 400 if the entity doesn't exist.
  (try
    (first (.getImages
            (.describeImages (ec2) (doto (DescribeImagesRequest.)
                                        (.setImageIds [(name image-id)])))))
    (catch AmazonServiceException e nil)))

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
              or a string or numeric AWS account ID.
   :filters - map of attributes/values to filter on.  Key (k/v can be keyword, string, or other for vals).
      architecture - The image architecture (i386 | x86_64).
      block-device-mapping.delete-on-termination - A Boolean value that indicates whether the Amazon EBS volume is deleted on instance termination.
      block-device-mapping.device-name - The device name for the Amazon EBS volume (for example, /dev/sdh).
      block-device-mapping.snapshot-id - The ID of the snapshot used for the Amazon EBS volume.
      block-device-mapping.volume-size - The volume size of the Amazon EBS volume, in GiB.
      block-device-mapping.volume-type - The volume type of the Amazon EBS volume (standard | io1).
      description - The description of the image (provided during image creation).
      hypervisor - The hypervisor type (ovm | xen).
      image-id - The ID of the image.
      image-type - The image type (machine | kernel | ramdisk).
      is-public - A Boolean that indicates whether the image is public.
      kernel-id - The kernel ID.
      manifest-location - The location of the image manifest.
      name - The name of the AMI (provided during image creation).
      owner-alias - The AWS account alias (for example, amazon).
      owner-id - The AWS account ID of the image owner.
      platform - The platform. To only list Windows-based AMIs, use windows.
      product-code - The product code.
      product-code.type - The type of the product code (devpay | marketplace).
      ramdisk-id - The RAM disk ID.
      root-device-name - The name of the root device volume (for example, /dev/sda1).
      root-device-type - The type of the root device volume (ebs | instance-store).
      state - The state of the image (available | pending | failed).
      state-reason-code - The reason code for the state change.
      state-reason-message - The message for the state change.
      tag:key=value - The key/value combination of a tag assigned to the resource.
      tag-key - The key of a tag assigned to the resource.
      tag-value - The value of a tag assigned to the resource.
      virtualization-type - The virtualization type (paravirtual | hvm). "
  [& {:keys [ids owned-by exec-by filters]}]
  (let [request (DescribeImagesRequest.)]
    (if ids (.setImageIds request (listify ids)))
    (if owned-by (.setOwners request (keys-n-stuff->strings (listify owned-by))))
    (if exec-by (.setExecutableUsers request (keys-n-stuff->strings (listify exec-by))))
    (if filters (.setFilters request (map->ec2-filters filters)))
    (seq (.getImages (.describeImages (ec2) request)))))

(defn report-images
  "Report on zero or more images (AMIs),
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
   Image-id may be a keyword or string.
   *TODO*: Doesn't presently support instance-stores, needs a deleteBundle for those."
  [image-id]
  {:pre [image-id]}
  (let [image-id (name image-id)
        images (describe-images :ids image-id)]
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

(defn image-exists?
  "Return true if the specified security image ID exists, false if it does not."
  [image-id]
  ;; Throws if the image ID does not exist.
  (try 
    (let [result (describe-images :ids image-id)]
      (= (count result) 1))
    (catch Exception e false)))


;;;
;;; Snapshots
;;;

(defn get-snapshot
  "Retrieve Snapshot given ID or nil if the snapshot doesn't exist.
   ID may be string or keyword."
  [snapshot-id]
  ;; .describeSnapshots may throw AmazonServiceException 400 if the snapshot
  ;; doesn't exist.
  (try
    (first (.getSnapshots
            (.describeSnapshots (ec2) (doto (DescribeSnapshotsRequest.)
                                        (.setSnapshotIds [(name snapshot-id)])))))
    (catch AmazonServiceException e nil)))


;;;
;;; Volumes
;;;

(defmulti  volume-id
  "Retrieve the volume id of a volume.
   If the argument is already an ID, return the identity."
  class)
(defmethod volume-id String [volume-id] volume-id)
(defmethod volume-id clojure.lang.Keyword [volume-id] (name volume-id))
(defmethod volume-id Volume [volume] (.getVolumeId volume))


(defn get-volume
  "Retrieve Volume given ID or nil if the Volume doesn't exist.
   ID may be string or keyword."
  [volume-id]
  ;; AmazonServiceException 400 if the entity doesn't exist.
  (try
    (first (.getVolumes
            (.describeVolumes (ec2) (doto (DescribeVolumesRequest.)
                                      (.setVolumeIds [(name volume-id)])))))
    (catch AmazonServiceException e nil)))

(defn volume-snapshot-ids
  "Retrieve snapshot ids for a given volume or volume id.
   The returned snapshots are basically backups of the volume, as opposed to the
   'source snapshot' of a volume which is the image from which a volume was initially created."
  [volume-or-id]
  (let [volume-id (volume-id volume-or-id)]
    (map #(.getSnapshotId %)
         (.getSnapshots
          (.describeSnapshots (ec2)
                              (doto (DescribeSnapshotsRequest.)
                                (.setFilters [(Filter. "volume-id" [volume-id])])))))))

;;;
;;; Subnets
;;;

(defn get-subnet
  "Retrieve Subnet given ID or nil if the Subnet doesn't exist.
   ID may be string or keyword."
  [subnet-id]
  ;; AmazonServiceException 400 if the entity doesn't exist.
  (try
    (first (.getSubnets
            (.describeSubnets (ec2) (doto (DescribeSubnetsRequest.)
                                      (.setSubnetIds [(name subnet-id)])))))
    (catch AmazonServiceException e nil)))


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
        descs (or (not-empty?
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
      ;; *TODO*/*TBD*: These instances can refer to non-existent instances!
      ;; Might be useful to look up the instance and report whether or not it actually exists.
      ;; A certain scribe relay ELB I know of had an invalid instance reference.
      (when-let [instances (and (:Instances fields)
                               (not-empty? (seq (.getInstances desc))))]
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


(defn- get-metrics-lazy
  "Fetch all metrics in paged fashion as a lazy sequence.
   'cw' is an AmazonCloudWatchClient instance.
   'result' is the seq of Metrics gathered so far.
   'nt' is the nextToken to fetch."
  [cw result nt]
  ;;(println "nt=" (str "'" nt "'") "cnt=" (count result))
  (if (and nt (> (count nt) 0))
    (concat result
            (lazy-seq 
             (let [metrics-result (.listMetrics
                                 cw (doto (ListMetricsRequest.) (.setNextToken nt)))]
               (get-metrics-lazy cw (.getMetrics metrics-result)
                                (.getNextToken metrics-result)))))
    result))

(def aws-metric-namespaces
  "Known 'AWS/<x>' namespaces per
   http://docs.aws.amazon.com/AmazonCloudWatch/latest/DeveloperGuide/aws-namespaces.html
   Unfortunately I don't know an API dedicated to returning this information,
   or the custom namespaces.  We'd have to clean it from all namespaces listed for
   all metrics which is expensive.  See 'get-all-metric-namespaces.'"
  (for [name 
        ["AutoScaling" "Billing" "DynamoDB" "ElastiCache" "EBS" "EC2" "ELB" "ElasticMapReduce"
         "OpsWorks" "Redshift" "RDS" "Route53" "SNS" "SQS" "SWF" "StorageGateway"]]
    (str "AWS/" name)))

(defn describe-metrics
  "Retrieve Metric instances.
   Options:
    :namespace - string specifying a namespace (no globs allowed)
                 whose metrics we're interested in. See 'get-all-metric-namespaces'
                 if you're not sure what those (namespaces) might be."
  ;; *TODO*: need filtering options
  [& {:keys [namespace]}]
  (let [cw (cw)
        request (ListMetricsRequest.)]
    (if namespace
      (.setNamespace request namespace))
    (let [metric-result (.listMetrics cw request)]
      (get-metrics-lazy cw (.getMetrics metric-result) (.getNextToken metric-result)))))

(defn get-all-metric-namespaces
  "Retrieve a set of all metric namespaces (in the current region)
   the hard (expensive) way.  For a set of precomputed 'standard' AWS namespaces
   see 'aws-metric-namespaces'."
  []
  (into #{}
    (map (fn [metric] (.getNamespace metric))
         (describe-metrics))))

(defn report-metrics
  "Report on zero or more Metric instances, fetch them if non are specified as with 'describe-metrics'.
  :instances a collection of Metric instances, optional."
  [& {:keys [instances]}]
  (let [instances (or instances (describe-metrics))]
    (doseq [metric instances]
      (print (.getMetricName metric)
             (.getNamespace metric))
      (doseq [dimension (.getDimensions metric)]
        (cl-format true " ~a=~a" (.getName dimension) (.getValue dimension)))
      (println))))

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
  :instances A collection of MetricAlarm instances, optional."
  [& {:keys [instances]}]
  ;; Note: non-lazy took 17.4 secs, lazy took 18.3 secs, for 1761 alarms
  ;; in 50 record batches (the default).  Could be normal statistical/network variance.
  ;; With 100 record batches: non-lazy 14.47 secs, lazy 14.74 secs
  (let [instances (or instances (describe-alarms-nonlazy))]
    (doseq [ma instances]               ;ma == metricAlarm
      (println (.getAlarmName ma)
               (.getMetricName ma)
               (.getAlarmDescription ma)))))
      
;;;
;;; Kitchen sink reports/tools
;;;

(defn print-instance-dependencies
  "Print the transitive closure of AWS environmental
   entities on which an instance or instance-id depends.
   This includes security groups, subnets,
   volumes, snapshots, AMIs, and so on.
   Also print a list of things that depend on the instance (auto-scaling groups, etc)."
  [instance-or-id]
  (let [instance (if (instance-id? instance-or-id)
                   (get-instance instance-or-id)
                   instance-or-id)
        volume-ids (atom ())
        print-tags (fn [indent tag-label tagDescriptions]
                     (if (empty? tagDescriptions)
                       (cl-format true "~V@T~a: <none>~%" indent tag-label)
                       (do
                         (cl-format true "~V@T~a:~%" indent tag-label)
                         (doseq [tag (sort-aws-tags tagDescriptions ["Name" "Project" "Creator"])]
                           (cl-format true "~V@T~s ~s~%" (+ 2 indent)
                             (.getKey tag) (.getValue tag))))))
        print-security-group-identifiers
        (fn [indent groupIdentifiers]
          (when groupIdentifiers
            (cl-format true "~V@TSecurity Groups:~%" indent)
            (doseq [group-id groupIdentifiers]
              (let [sg-id (.getGroupId group-id)
                    sg (get-security-group sg-id)]
                (cl-format true "~V@TId: ~a  Name: ~a  Vpc: ~a~%" (+ indent 2)
                  sg-id (.getGroupName group-id) (.getVpcId sg))
                (print-tags (+ indent 4) "Security Group Tags" (.getTags sg))))))
        ]

    (if-not instance
      (println "Instance" instance-or-id "does not exist.")
      (do
        (assert (instance? Instance instance))
        (cl-format true "~0@TInstance:~20T~a~%" (instance-id instance))
        (print-tags 2 "Instance Tags" (.getTags instance))
        (let [image-id (.getImageId instance)
              image (get-image image-id)]
          (cl-format true "~2@TAMI:~20T~a~%" image-id)
          (print-tags 4 "AMI Tags" (.getTags image))
          (when-let [bdms (.getBlockDeviceMappings image)] ; BlockDeviceMapping, not InstanceBlockDeviceMapping
            (when-let [ebs-bdms (filter #(.getEbs %) bdms)]
              (unless (empty? ebs-bdms)
                (cl-format true "~4@TEBS Block Devices:~%")
                (doseq [dev ebs-bdms]
                  (let [ebs-dev (.getEbs dev)
                        snapshot-id  (.getSnapshotId ebs-dev)
                        snapshot (get-snapshot snapshot-id)]
                    (cl-format true "~6@TDevice: ~a  Snapshot: ~a~a  Volume: ~a~%"
                      (.getDeviceName dev) snapshot-id
                      (if snapshot "" " (defunct)")
                      (if snapshot
                        (.getVolumeId snapshot)
                        "<unknown>"))
                    (when snapshot
                      (print-tags 6 "Snapshot Tags" (.getTags snapshot)))))))))
        (cl-format true "~2@TKernel:~20T~a~%" (.getKernelId instance))
        (when-let [vpc-id (.getVpcId instance)]
          (cl-format true "~2@TVPC:~20T~a~%" vpc-id)
          (let [vpc (get-vpc vpc-id)]
            (print-tags 4 "VPC Tags" (.getTags vpc))))
        (when-let [subnet-id (.getSubnetId instance)]
          (cl-format true "~2@TSubnet:~20T~a~%" subnet-id)
          (let [subnet (get-subnet subnet-id)]
            (print-tags 4 "Subnet Tags" (.getTags subnet))))
        (if-let [instance-profile (.getIamInstanceProfile instance)]
          (cl-format true "~2@TInstance Profile:~20T~a ~a~%"
            (.getId instance-profile) (.getArn instance-profile)))
        (if-let [key-name (.getKeyName instance)]
          (cl-format true "~2@TKey Pair:~20T~a~%" key-name))
        (print-security-group-identifiers 2 (.getSecurityGroups instance))
        (when-let [network-interfaces (.getNetworkInterfaces instance)]
          (unless (empty? network-interfaces)
            (cl-format true "~2@TNetwork Interfaces:~%")
            (doseq [ni network-interfaces]
              (cl-format true "~4@TId: ~a~%" (.getNetworkInterfaceId ni))
              (when-let [association (.getAssociation ni)] ;InstanceNetworkInterfaceAssociation
                (cl-format true "~6@TEIP: ~20T~a~%" (.getPublicIp association))
                (cl-format true "~8@TIP Owner Id: ~a~%" (.getIpOwnerId association))
                (cl-format true "~8@TPublic DNS: ~a~%" (.getPublicDnsName association)))
              (when-let [attachment (.getAttachment ni)] ; InstanceNetworkInterfaceAttachment
                (cl-format true "~6@TAttachment: ~a at index ~%"
                  (.getAttachmentId attachment) (.getDeviceIndex attachment)))
              (print-security-group-identifiers 6 (.getGroups ni)))))
        (when-let [ibdms (.getBlockDeviceMappings instance)] ; InstanceBlockDeviceMapping
          (when-let [ebs-ibdms (filter #(.getEbs %) ibdms)]
            (unless (empty? ebs-ibdms)
              (cl-format true "~2@TEBS Block Devices:~%")
              (doseq [dev ebs-ibdms]
                (let [ebs-dev (.getEbs dev)]
                  (let [volume-id  (.getVolumeId ebs-dev)
                        volume (get-volume volume-id)
                        volume-tags (.getTags volume)
                        source-snapshot-id (.getSnapshotId volume)] ; from which volume was created
                    (swap! volume-ids conj volume-id)
                    (cl-format true "~4@TDevice: ~a  Volume: ~a~%"
                      (.getDeviceName dev) volume-id)
                    (print-tags 6 "Volume Tags" volume-tags)
                    (when source-snapshot-id
                      (let [snapshot (get-snapshot source-snapshot-id)]
                        (cl-format true "~6@TSource Snapshot: ~a~a~%"
                          source-snapshot-id
                          (if snapshot "" " (defunct)"))
                        (if snapshot
                          (print-tags 8 "Source Snapshot Tags"
                                      (.getTags snapshot)))))
                    ))))))
        ;; Done with the instance itself.  Print supplementary
        ;; data about things referencing the instance its dependencies.
        (unless (empty? @volume-ids)
          (println)
          (println "Snapshots taken of the above EBS volumes:")
          (doseq [volume-id @volume-ids]
            (let [snapshot-ids (volume-snapshot-ids volume-id)]
              (unless (empty? snapshot-ids)
                (cl-format true "~2@TVolume ~a~%" volume-id)
                (doseq [snapshot-id snapshot-ids]
                  ;; TODO Faster if we fetch all snapshots with one describe-snapshots call.
                  ;; But describe-snapshots wasn't implemented when I wrote this
                  (when-let [snapshot (get-snapshot snapshot-id)]
                    (cl-format true "~4@TSnapshot ~a~%" snapshot-id)
                    (print-tags 6 "Snapshot Tags" (.getTags snapshot))))))))))
    ))

;; *TODO* in print-instance-dependencies:
;; ELBs that point to instance.
;; auto-scaling, route53, and other references to instance
;; Can tag auto scaling groups, but not launch configurations.

;; Note on ec2-describe-* --filter "tag:Name=*xyzzy*"
;; The API is case sensitive for values, however the CONSOLE
;; is not.  They must build a key set for searching and use a different search
;; method when you filter via the console.
