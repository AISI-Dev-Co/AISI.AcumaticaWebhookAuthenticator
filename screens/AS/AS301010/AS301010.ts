import {
	createCollection,
	PXScreen,
	graphInfo,
	viewInfo,
	PXView,
	columnConfig,
	gridConfig,
	PXFieldState,
	PXFieldOptions,
	GridPreset
} from "client-controls";

@graphInfo({graphType: "AISI.AcumaticaWebhookAuthenticator.Acumatica.AISIWebhookRetryProc", primaryView: "Retries"})
export class AS301010 extends PXScreen {

	@viewInfo({ containerName: "Retries" })
	Retries = createCollection(AISIWebhookRetry);
}

@gridConfig({
	preset: GridPreset.Processing
})
export class AISIWebhookRetry extends PXView {
	@columnConfig({ allowCheckAll: true })
	Selected: PXFieldState<PXFieldOptions.CommitChanges>;
	WebHookID: PXFieldState;
	ReceivedOn: PXFieldState;
	Status: PXFieldState;
	AttemptCount: PXFieldState;
	LastAttemptOn: PXFieldState;
	TraceIdentifier: PXFieldState;
	HandlerType: PXFieldState;
	Method: PXFieldState;
	ContentType: PXFieldState;
	FailureMessage: PXFieldState;
}
