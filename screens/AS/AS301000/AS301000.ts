import {
	createCollection,
	createSingle,
	PXScreen,
	graphInfo,
	PXView,
	PXActionState,
	gridConfig,
	PXFieldState,
	PXFieldOptions,
	GridPreset
} from "client-controls";

@graphInfo({graphType: "AISI.AcumaticaWebhookAuthenticator.Acumatica.AISIWebhookSecretMaint", primaryView: "Secrets"})
export class AS301000 extends PXScreen {

	GenerateSecret: PXActionState;
	RotateSecret: PXActionState;

	Secrets = createCollection(AISIWebhookSecret);
	Reveal = createSingle(AISIWebhookSecretReveal);
}

@gridConfig({
	preset: GridPreset.Primary
})
export class AISIWebhookSecret extends PXView {
	WebHookID: PXFieldState<PXFieldOptions.CommitChanges>;
	SecretEncoding: PXFieldState;
	Secret: PXFieldState;
	RotatingSecret: PXFieldState;
	RotatingExpiresOn: PXFieldState;
	AllowedAddresses: PXFieldState;
	ClientAddressHeader: PXFieldState;
	TrustedProxyDepth: PXFieldState;
}

export class AISIWebhookSecretReveal extends PXView {
	NewSecret: PXFieldState;
}
