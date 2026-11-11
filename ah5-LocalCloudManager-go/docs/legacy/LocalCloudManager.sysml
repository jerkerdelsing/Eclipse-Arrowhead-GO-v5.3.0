package LocalCloudManagerVariability {
    doc /* Arrowhead 5.2.2 LocalCloudManager contract and its three substitutable implementations. */

    port def LocalCloudManagementPort;
    port def ServiceRegistryClientPort;
    port def DataManagerClientPort;
    port def OrchestrationClientPort;
    port def RuntimeControlPort;
    port def OperatorUIPort;

    part def LocalCloudManagerContract {
        port localCloudManagement : LocalCloudManagementPort;
        port operatorUI : OperatorUIPort;
        port serviceRegistry : ~ServiceRegistryClientPort;
        port dataManager : ~DataManagerClientPort;
        port orchestration : ~OrchestrationClientPort;
        port runtimeControl : ~RuntimeControlPort;
        attribute operatorSession : String = "scrypt password; HttpOnly SameSite=Strict cookie";
        attribute consoleViews : String = "OV, SR, SY, SV, OR, PD, CS, DM, SM, IC, RT";
        attribute requestProtection : String = "Host and Origin allow-list";
    }

    part def JavaCloudLocalCloudManager :> LocalCloudManagerContract {
        doc /* Node.js adapter deployed with the Java 5.2.2 test cloud; UI port 8080. */
    }

    part def GoLocalCloudManager :> LocalCloudManagerContract {
        doc /* Native Go implementation in Arrowhead-test-cloud-go; API 9480 and UI 9490. */
    }

    part def RustLocalCloudManager :> LocalCloudManagerContract {
        doc /* Native Rust/Axum implementation in Arrowhead-test-cloud-rust; API 8580 and UI 8590. */
    }

    variation part def LocalCloudManagerImplementation :> LocalCloudManagerContract {
        variant javaCloud : JavaCloudLocalCloudManager;
        variant go : GoLocalCloudManager;
        variant rust : RustLocalCloudManager;
    }

    part def ArrowheadLocalCloudWithManager {
        variation part localCloudManager : LocalCloudManagerImplementation[1] {
            variant javaCloud;
            variant go;
            variant rust;
        }
    }
}
