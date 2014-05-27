(defproject jaws "0.1.0"
  :description "Some simple tool type wrappers for amazon aws JDK API"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [com.amazonaws/aws-java-sdk "1.7.3"] ; for native.clj
                 [jdt "0.1.2"] ; jdt.{core,cl,shell,java,easyfs,ssh}
                 ]

  ;; These are for "application" mode.  Comment out for development.
  ;; And note that if :profiles is specified, it basically overrides (for the project) the
  ;; maps in ~/.lein/profiles.clj
;  :main ^:skip-aot jaws.core
;  :target-path "target/%s"
;  :profiles {:uberjar {:aot :all}}
  )
