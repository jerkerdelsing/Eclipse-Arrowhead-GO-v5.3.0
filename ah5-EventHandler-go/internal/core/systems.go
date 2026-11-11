// SPDX-License-Identifier: EPL-2.0
package core

type System struct {
	Name, Base, Purpose string
	Services            []string
}

var Systems = map[string]System{
	"Blacklist":              {"Blacklist", "/blacklist", "Time-bounded system exclusion and discovery", []string{"blacklistDiscovery", "blacklistManagement"}},
	"Configuration":          {"Configuration", "/configuration", "Versioned configuration storage and retrieval", []string{"configuration", "configurationProxy", "configurationManagement"}},
	"DataManager":            {"DataManager", "/datamanager", "SenML historian and authorized provider data proxy", []string{"dataProxy", "dataHistorian"}},
	"TimeManager":            {"TimeManager", "/timemanager", "UTC reference time", []string{"time"}},
	"EventHandler":           {"EventHandler", "/eventhandler", "Authorized subscriptions and event delivery", []string{"eventPublish", "eventSubscription", "eventHandlerManagement"}},
	"DeviceQoSEvaluator":     {"DeviceQoSEvaluator", "/deviceqosevaluator", "Device measurement filtering and ranking", []string{"qualityEvaluation", "deviceQualityDataManagement"}},
	"AIGym":                  {"AIGym", "/aigym", "Local extension: nearest-neighbour model training and inference", []string{"aiGym"}},
	"PlantDescriptionEngine": {"PlantDescriptionEngine", "/plantdescriptionengine", "Plant topology and monitored alarm state", []string{"plantDescriptionManagement", "plantDescriptionMonitor"}},
	"Choreographer":          {"Choreographer", "/choreographer", "Plan, executor and dependency-ordered session management", []string{"choreographerSession", "choreographerExecutor", "choreographerManagement"}},
	"CertificateAuthority":   {"CertificateAuthority", "/certificate-authority", "Profile-constrained CSR issuance, revocation and trusted keys", []string{"certificateSigning", "certificateValidation", "certificateAuthorityManagement"}},
	"SysMonitor":             {"SysMonitor", "/sysmonitor", "Monitoring subscriptions, history and durable observation forwarding", []string{"sysMonitorManagement", "sysMonitorHistory", "sysMonitorData"}},
	"Onboarding":             {"Onboarding", "/onboarding", "Controlled certificate, device and system onboarding", []string{"onboarding", "onboardingManagement"}},
	"TestTranslation":        {"TestTranslation", "/testtranslation", "Test system: generic_https interface translator and simpleJson/senml data model translator", []string{"interfaceBridgeManagement", "dataModelTranslation"}},
	"TranslationManager":     {"TranslationManager", "/translation", "Bridge discovery, negotiation and lifecycle", []string{"translationReport", "translationBridge", "translationBridgeManagement"}},
	"Gatekeeper":             {"Gatekeeper", "/gatekeeper", "Cross-cloud discovery and negotiation", []string{"globalServiceDiscovery", "interCloudNegotiation", "gatekeeperManagement"}},
	"GateTunnel":             {"GateTunnel", "/gatetunnel", "Authorized legacy-mTLS relay and tunnel sessions", []string{"gateTunnelConnection", "gateTunnelKey", "gateTunnelManagement"}},
}
