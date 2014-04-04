(defproject jaws "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.5.1"]
                 [amazonica "0.2.10"]   ;for core.clj
                 [com.amazonaws/aws-java-sdk "1.7.3"] ; for native.clj
                 ;;[ch.ethz.ganymed/ganymed-ssh2 "261"] ; ssh
                 [jdt "0.1.0-SNAPSHOT"] ; jdt.{core,cl,shell,java}
                 [org.clojure/tools.logging "0.2.6"]
                 ]

  ;; These are for "application" mode.  Comment out for development.
  ;; And note that if :profiles is specified, it basically overrides (for the project) the
  ;; maps in ~/.lein/profiles.clj
;  :main ^:skip-aot jaws.core
;  :target-path "target/%s"
;  :profiles {:uberjar {:aot :all}}
  )
