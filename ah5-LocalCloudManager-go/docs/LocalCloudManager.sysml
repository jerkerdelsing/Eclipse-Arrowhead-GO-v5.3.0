package LocalCloudManagerImplementations {
    doc /* Implementation variability, not a declaration of proven substitution. */
    port def OperatorUIPort;
    port def LocalCloudManagementPort;
    port def SysMonitorPublisherPort;
    port def ProviderClientPort;
    port def RuntimeControlPort;
    part def LocalCloudManagerContract {
        port operatorUI : OperatorUIPort;
        port localCloudManagement : LocalCloudManagementPort;
        port sysMonitor : SysMonitorPublisherPort;
        port providers : ~ProviderClientPort;
        port runtime : ~RuntimeControlPort;
        attribute systemVersion : String = "5.2.2";
        attribute serviceVersion : String = "1.0.0";
    }
    part def JavaCloudManager :> LocalCloudManagerContract {
        attribute sourceLocation : String = "ah5-support-java-spring/LocalCloudManager";
        attribute implementation : String = "Existing Java-cloud Node.js adapter; not Java-language source";
    }
    part def GoCloudManager :> LocalCloudManagerContract {
        attribute sourceLocation : String = "ah5-support-go/LocalCloudManager";
        attribute implementation : String = "Native Go, embedded UI, isolated nested module";
        attribute qualification : String = "Relocated development implementation; Java parity not proven";
        attribute deploymentSnapshot : String = "Arrowhead-test-cloud-go/native-go retained unchanged";
        attribute limitations : String = "Subscription writes no-op; intercloud placeholder; synthetic status; localhost cookie/origin separation incomplete";
    }
    part def RustCloudManager :> LocalCloudManagerContract {
        attribute sourceLocation : String = "Arrowhead-test-cloud-rust/core-systems/src/localcloudmanager.rs";
        attribute qualification : String = "Existing Rust source; not requalified by Go relocation";
    }
    variation part def SelectedManager :> LocalCloudManagerContract {
        variant javaCloud : JavaCloudManager;
        variant go : GoCloudManager;
        variant rust : RustCloudManager;
    }
}
