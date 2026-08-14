import {
	createCollection,
	PXScreen,
	graphInfo,
	PXView,
	columnConfig,
	gridConfig,
	PXFieldState,
	PXFieldOptions,
	GridPreset
} from "client-controls";

@graphInfo({graphType: "AISI.AcumaticaWebhookAuthenticator.Acumatica.AISIWebhookSecretMaint", primaryView: "Secrets"})
export class AS301000 extends PXScreen {

	Secrets = createCollection(AISIWebhookSecret);
}

@gridConfig({
	preset: GridPreset.Primary
})
export class AISIWebhookSecret extends PXView {
	WebHookID: PXFieldState<PXFieldOptions.CommitChanges>;
	Secret: PXFieldState;
	RotatingSecret: PXFieldState;
	RotatingExpiresOn: PXFieldState;
	AllowedAddresses: PXFieldState;
	ClientAddressHeader: PXFieldState;
	TrustedProxyDepth: PXFieldState;
}
