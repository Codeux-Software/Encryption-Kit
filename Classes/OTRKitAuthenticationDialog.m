/* *********************************************************************

        Copyright (c) 2010 - 2015 Codeux Software, LLC
     Please see ACKNOWLEDGEMENT for additional information.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:

 * Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
 * Neither the name of "Codeux Software, LLC", nor the names of its 
   contributors may be used to endorse or promote products derived 
   from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 SUCH DAMAGE.

 *********************************************************************** */

#import "OTRKitAuthenticationDialogPrivate.h"

#include <objc/message.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wincomplete-implementation"

#pragma mark -
#pragma mark OTRKitAuthenticationDialog Implementation

@implementation OTRKitAuthenticationDialog

+ (void)requestAuthenticationForUsername:(NSString *)username accountName:(NSString *)accountName protocol:(NSString *)protocol
{
	CheckParamaterForNilValue(username)
	CheckParamaterForNilValue(accountName)
	CheckParamaterForNilValue(protocol)

	OTRKitAuthenticationDialog *openDialogs = [[OTRKitAuthenticationDialogWindowManager sharedManager] dialogForUsername:username
																											 accountName:accountName
																												protocol:protocol];

	if ( openDialogs) {
		[openDialogs bringHostWindowForward];
	} else {
		OTRKitAuthenticationDialogOutgoing *outgoingRequest = [OTRKitAuthenticationDialogOutgoing new];

		[outgoingRequest setIsIncomingRequest:NO];

		[outgoingRequest setCachedUsername:username];
		[outgoingRequest setCachedAccountName:accountName];

		[outgoingRequest setCachedProtocol:protocol];

		[[OTRKitAuthenticationDialogWindowManager sharedManager] addDialog:outgoingRequest];

		[outgoingRequest authenticateUser];
	}
}

+ (void)handleAuthenticationRequest:(OTRKitSMPEvent)event progress:(double)progress question:(NSString *)question username:(NSString *)username accountName:(NSString *)accountName protocol:(NSString *)protocol
{
	CheckParamaterForNilValue(username)
	CheckParamaterForNilValue(accountName)
	CheckParamaterForNilValue(protocol)

	OTRKitAuthenticationDialog *openDialogs = [[OTRKitAuthenticationDialogWindowManager sharedManager] dialogForUsername:username
																											 accountName:accountName
																												protocol:protocol];

	if (event == OTRKitSMPEventAskForAnswer || event == OTRKitSMPEventAskForSecret) {
		if (openDialogs) {
			if ([openDialogs isIncomingRequest] == NO) {
				[[OTRKit sharedInstance] abortSMPForUsername:username
												 accountName:accountName
													protocol:protocol];
			}

			[openDialogs presentDialogAlreadyExistsErrorAlert];

			return; // Do not further event...
		} else {
			 openDialogs = [OTRKitAuthenticationDialogIncoming new];

			[openDialogs setIsIncomingRequest:YES];

			[openDialogs setCachedUsername:username];
			[openDialogs setCachedAccountName:accountName];

			[openDialogs setCachedProtocol:protocol];

			[[OTRKitAuthenticationDialogWindowManager sharedManager] addDialog:openDialogs];
		}
	}

	[openDialogs handleEvent:event progress:progress question:question];
}

+ (void)showFingerprintConfirmation:(NSWindow *)hostWindow username:(NSString *)username accountName:(NSString *)accountName protocol:(NSString *)protocol
{
	CheckParamaterForNilValue(username)
	CheckParamaterForNilValue(accountName)
	CheckParamaterForNilValue(protocol)

	OTRKitAuthenticationDialog *openDialogs = [[OTRKitAuthenticationDialogWindowManager sharedManager] dialogForUsername:username
																											 accountName:accountName
																												protocol:protocol];

	if (openDialogs) {
		LogToConsole(@"Tried to open a dialog when one was already open.");
	} else {
		OTRKitAuthenticationDialogOutgoing *incomingRequest = [OTRKitAuthenticationDialogOutgoing new];

		[incomingRequest setIsIncomingRequest:NO];

		[incomingRequest setCachedUsername:username];
		[incomingRequest setCachedAccountName:accountName];

		[incomingRequest setCachedProtocol:protocol];

		[incomingRequest setApplicationHostWindow:hostWindow];

		[[OTRKitAuthenticationDialogWindowManager sharedManager] addDialog:incomingRequest];

		[incomingRequest showFingerprintConfirmationForTheirHash];
	}
}

+ (void)cancelRequestForUsername:(NSString *)username accountName:(NSString *)accountName protocol:(NSString *)protocol
{
	CheckParamaterForNilValue(username)
	CheckParamaterForNilValue(accountName)
	CheckParamaterForNilValue(protocol)

	OTRKitAuthenticationDialog *openDialogs = [[OTRKitAuthenticationDialogWindowManager sharedManager] dialogForUsername:username accountName:accountName protocol:protocol];

	if ( openDialogs) {
		[openDialogs cancelRequest];
	} else {
		LogToConsole(@"Tried to cancel a request for a dialog that does not exist.");
	}
}

#pragma mark -
#pragma mark Dialog Construction

- (instancetype)init
{
	if ((self = [super init])) {
		[self prepareInitialState];

		return self;
	}

	return nil;
}

- (void)prepareInitialState
{
	/* Observe notifications for when the application will terminate so that we can
	 tear down the dialog gracefully instead of allowing OS X to shove its memory aside. */
	[[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(applicationWillTerminateNotification:) name:OTRKitPrepareForApplicationTerminationNotification object:nil];
}

- (void)applicationWillTerminateNotification:(NSNotification *)notification
{
	/* Invoke -cancelRequest so that an abort signal can be sent if it must. */
	[self cancelRequest];
}

- (void)bringHostWindowForward
{
	[[self authenticationHostWindow] makeKeyAndOrderFront:nil];
}

- (void)changeContentViewTo:(NSView *)contentView
{
	/* Remove any views that may already be in place. */
	NSArray *contentSubviews = [[self contentView] subviews];

	if ([contentSubviews count] > 0) {
		[contentSubviews[0] removeFromSuperview];
	}

	/* Set constraints and add the new view. */
	[[self contentViewHeightConstraint] setConstant:NSHeight([contentView frame])];

	[[self contentView] addSubview:contentView];
}

- (void)formatTextField:(NSTextField *)textField withUsername:(NSString *)username
{
	/* Many text fields contain a formatting character (%@) in the interface. This
	 takes that text field value and formats it using the given username. Easier 
	 doing it this way than maining a strings file. */
	NSString *currentTextFieldValue = [textField stringValue];

	NSString *formattedStringValue = [NSString stringWithFormat:currentTextFieldValue, username];

	[textField setStringValue:formattedStringValue];
}

- (void)updateButtonEnabledState
{
	/* Update the Ok and Cancel buttons of the host window depending on values. */
	/* When sent, the values in the text field are not trimmed of whitespaces, but
	 we do it below to try and check validity as best as possible. */
	BOOL okButtonEnabled = YES;

	if ([self authenticationMethod] == OTRKitSMPEventAskForAnswer)
	{
		NSString *question = [[self questionAndAnswerQuestionTextField] stringValue];
		NSString *answer = [[self questionAndAnswerAnswerTextField] stringValue];

		NSString *trimmedQuestion = [question stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];;
		NSString *trimmedAnswer = [answer stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

		okButtonEnabled = ([trimmedQuestion length] > 0 && [trimmedAnswer length] > 0);
	}
	else if ([self authenticationMethod] == OTRKitSMPEventAskForSecret)
	{
		NSString *secret = [[self sharedSecretAnswerTextField] stringValue];

		NSString *trimmedSecret = [secret stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

		okButtonEnabled = ([trimmedSecret length] > 0);
	}

	/* Update buttons with their status. */
	[[self authenticationHostWindowAuthenticateButton] setEnabled:okButtonEnabled];

	[[self authenticationHostWindowCancelButton] setEnabled:YES];
}

- (void)controlTextDidChange:(NSNotification *)obj
{
	[self updateButtonEnabledState];
}

- (NSString *)localizedString:(NSString *)original, ...
{
	va_list args;
	va_start(args, original);

	NSString *formattedString = [OTRKitFrameworkHelpers localizedString:original inTable:@"OTRKitAuthenticationDialog" arguments:args];

	va_end(args);

	return formattedString;
}

- (NSWindow *)deepestSheetOfWindow:(NSWindow *)window
{
	/* Recursively scan all attached sheets until we find a window without one. */
	NSWindow *attachedSheet = [window attachedSheet];

	if (attachedSheet) {
		return [self deepestSheetOfWindow:attachedSheet];
	} else {
		return window;
	}
}

- (void)presentAlert:(NSString *)messageText informativeText:(NSString *)informativeText buttons:(NSArray *)buttons didEndSelector:(SEL)didEndSelector
{
	/* Construct alert */
	NSAlert *errorAlert = [NSAlert new];

	[errorAlert setAlertStyle:NSInformationalAlertStyle];

	[errorAlert setMessageText:messageText];
	[errorAlert setInformativeText:informativeText];

	if (buttons == nil) {
		[errorAlert addButtonWithTitle:[self localizedString:@"00012"]]; // "OK" label
	} else {
		for (NSString *button in buttons) {
			[errorAlert addButtonWithTitle:button];
		}
	}

	/* Attach the sheet to the highest window */
	NSWindow *hostWindow = nil;

	if ([[self authenticationHostWindow] isVisible]) {
		hostWindow = [self deepestSheetOfWindow:[self authenticationHostWindow]];
	} else if ([self applicationHostWindow]) {
		hostWindow = [self deepestSheetOfWindow:[self applicationHostWindow]];
	}

	if (didEndSelector == NULL) {
		didEndSelector = @selector(alertSheetDidEnd:returnCode:contextInfo:);
	}

	if (hostWindow) {
		[errorAlert beginSheetModalForWindow:hostWindow
							   modalDelegate:self
							  didEndSelector:didEndSelector
								 contextInfo:NULL];
	} else {
		NSModalResponse returnCode = [errorAlert runModal];

		objc_msgSend(self, didEndSelector, errorAlert, returnCode, NULL);
	}
}

- (void)alertSheetDidEnd:(NSAlert *)alert returnCode:(NSInteger)returnCode contextInfo:(void *)contextInfo
{
	;
}

- (void)presentDialogAlreadyExistsErrorAlert
{
	/* Do not show alert multiple times */
	if ([self dialogAlreadyExistsErrorAlertIsVisible]) {
		return; // Cancel operation...
	}

	/* Get the visible portion of the remote user's name. */
	NSString *username = [[OTRKit sharedInstance] leftPortionOfAccountName:[self cachedUsername]];

	/* Construct error messages */
	NSString *messageText = [self localizedString:@"00010[1]"];

	NSString *descriptionText = [self localizedString:@"00010[2]", username];

	/* Construct and present alert */
	[self setDialogAlreadyExistsErrorAlertIsVisible:YES];

	[self presentAlert:messageText informativeText:descriptionText buttons:nil didEndSelector:NULL];
}

- (void)presentRemoteUserAbortedRequestDialog
{
	/* Get the visible portion of the remote user's name. */
	NSString *username = [[OTRKit sharedInstance] leftPortionOfAccountName:[self cachedUsername]];

	/* Construct error messages */
	NSString *messageText = [self localizedString:@"00011[1]"];

	NSString *descriptionText = [self localizedString:@"00011[2]", username];

	/* Mark the dialog as stale */
	[[OTRKitAuthenticationDialogWindowManager sharedManager] markDialogAsStale:self];

	/* Construct and present alert */
	[self presentAlert:messageText informativeText:descriptionText buttons:nil didEndSelector:@selector(presentRemoteUserAbortedRequestDialogAlertDidEnd:returnCode:contextInfo:)];
}

- (void)presentPrivateConversationIsNotActiveAlert
{
	/* Get the visible portion of the remote user's name. */
	NSString *username = [[OTRKit sharedInstance] leftPortionOfAccountName:[self cachedUsername]];

	/* Construct error messages */
	NSString *messageText = [self localizedString:@"00013[1]"];

	NSString *descriptionText = [self localizedString:@"00013[2]", username];

	/* Construct and present alert */
	[self presentAlert:messageText informativeText:descriptionText buttons:nil didEndSelector:NULL];
}

- (void)presentRemoteUserAbortedRequestDialogAlertDidEnd:(NSAlert *)alert returnCode:(NSInteger)returnCode contextInfo:(void *)contextInfo
{
	dispatch_async(dispatch_get_main_queue(), ^{
		if (returnCode == NSAlertFirstButtonReturn) {
			[self teardownDialog];
		}
	});
}

#pragma mark -
#pragma mark Teardown Dialog

- (void)maybeAbortOpenNegotations
{
	/* If a negotation is in progres, abort it. */
	if ([self lastEvent] == OTRKitSMPEventInProgress ||
		[self lastEvent] == OTRKitSMPEventAskForAnswer ||
		[self lastEvent] == OTRKitSMPEventAskForSecret)
	{
		[[OTRKit sharedInstance] abortSMPForUsername:[self cachedUsername]
										 accountName:[self cachedAccountName]
											protocol:[self cachedProtocol]];
	}
}

- (void)markUserVerified:(BOOL)isVerified
{
	/* Inform OTRKit of the change. */
	[[OTRKit sharedInstance] setActiveFingerprintVerificationForUsername:[self cachedUsername]
															 accountName:[self cachedAccountName]
																protocol:[self cachedProtocol]
																verified:isVerified];
}

- (void)cancelRequest
{
	/* Cancel any open negotations. */
	[self maybeAbortOpenNegotations];

	/* Tear down the dialog. */
	[self teardownDialog];
}

- (void)teardownDialog
{
	/* Remove any active notification observers */
	[[NSNotificationCenter defaultCenter] removeObserver:self];

	/* Tear down windows */
	[self endProgressIndicatorWindow];

	[self closeHostWindow];

	/* Remove any reference to this dialog. */
	[[OTRKitAuthenticationDialogWindowManager sharedManager] removeDialog:self];
}

- (void)closeHostWindow
{
	/* Close the host window if visible. */
	if ([[self authenticationHostWindow] isVisible]) {
		[[self authenticationHostWindow] close];
	}
}

#pragma mark -
#pragma mark Progress Indicator

- (void)setLastEvent:(OTRKitSMPEvent)lastEvent
{
	/* Update last event and possibly progress information. */
	if (_lastEvent != lastEvent) {
		_lastEvent = lastEvent;

		if ([[self authenticationProgressWindow] isVisible]) {
			[self updateProgressIndicatorButtonsWithEvent:lastEvent];
		}
	}
}

- (void)setAuthenticationMethod:(OTRKitSMPEvent)authenticationMethod
{
	/* Switch views when authentication method changes. */
	if (_authenticationMethod != authenticationMethod) {
		_authenticationMethod = authenticationMethod;

		if (authenticationMethod == OTRKitSMPEventNone) {
			[self changeContentViewTo:[self contentViewFingerprintAuthentication]];
		} else if (authenticationMethod == OTRKitSMPEventAskForAnswer) {
			[self changeContentViewTo:[self contentViewQuestionAndAnswerAuthentication]];
		} else if (authenticationMethod == OTRKitSMPEventAskForSecret) {
			[self changeContentViewTo:[self contentViewSharedSecretAuthentication]];
		} else {
			NSAssert(NO, @"Bad authenticationMethod value");
		}
	}
}

- (void)handleEvent:(OTRKitSMPEvent)event progress:(double)progress question:(NSString *)question
{
	/* Update status information for event. */
	[self setLastEvent:event];

	/* Update progress information based on event. */
	if ([[self authenticationProgressWindow] isVisible]) {
		[self updateProgressIndicatorPercentage:progress];
	}
}

- (void)setupProgressIndicatorWindow
{
	/* Get the visible portion of the remote user's name. */
	NSString *username = [[OTRKit sharedInstance] leftPortionOfAccountName:[self cachedUsername]];

	/* Format the title of the progress window with the remote user's name. */
	[self formatTextField:[self authenticationProgressTitleTextField] withUsername:username];

	/* Zero out the current progress indicator. */
	[[self authenticationProgressProgressIndicator] setDoubleValue:0.0];

	/* Present the sheet. */
	[NSApp beginSheet:[self authenticationProgressWindow]
	   modalForWindow:[self authenticationHostWindow]
		modalDelegate:self
	   didEndSelector:@selector(didEndAuthenticationProgressWindowSheet:returnCode:contextInfo:)
		  contextInfo:NULL];

	/* Fake our last event so that -maybeAbortOpenNegotations will work. */
	[self setLastEvent:OTRKitSMPEventInProgress];
}

- (void)didEndAuthenticationProgressWindowSheet:(NSWindow *)sheet returnCode:(NSInteger)returnCode contextInfo:(void *)contextInfo
{
	[sheet close];
}

- (void)updateProgressIndicatorStatusMessage:(NSString *)statusMessage
{
	/* Set the status message of the current progress window. */
	[[self authenticationProgressStatusTextField] setStringValue:statusMessage];
}

- (void)updateProgressIndicatorPercentage:(double)progress
{
	/* Set the progress of the current progress window. */
	[[self authenticationProgressProgressIndicator] setDoubleValue:progress];
}

- (void)updateProgressIndicatorButtonsWithEvent:(OTRKitSMPEvent)event
{
	/* Update progress status based on given event. */
	BOOL enableOkButton = NO;
	BOOL enableCancelButton = NO;

	if (event == OTRKitSMPEventCheated || event == OTRKitSMPEventError) {
		enableOkButton = YES;

		[self updateProgressIndicatorStatusMessage:[self localizedString:@"00005"]];
	} else if (event == OTRKitSMPEventInProgress) {
		enableCancelButton = YES;

		[self updateProgressIndicatorStatusMessage:[self localizedString:@"00001"]];
	} else if (event == OTRKitSMPEventFailure) {
		enableOkButton = YES;

		[self updateProgressIndicatorStatusMessage:[self localizedString:@"00003"]];
	} else if (event == OTRKitSMPEventAbort) {
		enableOkButton = YES;

		[self updateProgressIndicatorStatusMessage:[self localizedString:@"00004"]];
	} else if (event == OTRKitSMPEventSuccess) {
		enableOkButton = YES;

		[self updateProgressIndicatorStatusMessage:[self localizedString:@"00002"]];
	}

	/* Update buttons with their status. */
	[[self authenticationProgressOkButton] setEnabled:enableOkButton];
	[[self authenticationProgressCancelButton] setEnabled:enableCancelButton];
}

- (void)endProgressIndicatorWindow
{
	/* Close the current progress window if open. */
	if ([[self authenticationProgressWindow] isSheet]) {
		[NSApp endSheet:[self authenticationProgressWindow]];
	}
}

- (IBAction)authenticationProgressCancel:(id)sender
{
	/* Close negotation if it is open. */
	[self maybeAbortOpenNegotations];
	
	/* We cannot incoming outgoing authentication, so tear down window. */
	if ([self isIncomingRequest]) {
		[self teardownDialog];
	} else {
		[self endProgressIndicatorWindow];
	}
}

- (IBAction)authenticationProgressOk:(id)sender
{
	/* If the last event was successful, then we can tear down the entire
	 dialog, not just the pgoress indicator, because we are done here. */
	if ([self lastEvent] == OTRKitSMPEventSuccess) {
		[self teardownDialog]; // Will close progress window for us...
	} else {
		/* There is no way to resend failed requests for incoming. */
		if ([self isIncomingRequest]) {
			[self teardownDialog];
		} else {
			[self endProgressIndicatorWindow];
		}
	}
}

@end

#pragma mark -
#pragma mark OTRKitAuthenticationDialogIncoming Implementation

@implementation OTRKitAuthenticationDialogIncoming

- (instancetype)init
{
	if ((self = [super init])) {
		[[NSBundle bundleForClass:[self class]] loadNibNamed:@"OTRKitAuthenticationDialogIncoming" owner:self topLevelObjects:nil];

		return self;
	}

	return nil;
}

- (void)cancelAuthentication:(id)sender
{
	[self cancelRequest];
}

- (void)performAuthentication:(id)sender
{
	/* Check the message state for this user. */
	OTRKitMessageState messageState = [[OTRKit sharedInstance] messageStateForUsername:[self cachedUsername]
																		   accountName:[self cachedAccountName]
																			  protocol:[self cachedProtocol]];

	if (messageState == OTRKitMessageStateFinished ||
		messageState == OTRKitMessageStatePlaintext)
	{
		[self presentPrivateConversationIsNotActiveAlert];

		return; // Cancel operation...
	}

	/* Start a negoation depending on which method was selected. */
	NSString *secretAnswer = nil;

	if ([self authenticationMethod] == OTRKitSMPEventAskForAnswer) {
		secretAnswer = [[self questionAndAnswerAnswerTextField] stringValue];
	} else if ([self authenticationMethod] == OTRKitSMPEventAskForSecret) {
		secretAnswer = [[self sharedSecretAnswerTextField] stringValue];
	}

	if (secretAnswer) {
		[[OTRKit sharedInstance] respondToSMPForUsername:[self cachedUsername]
											 accountName:[self cachedAccountName]
												protocol:[self cachedProtocol]
												  secret:secretAnswer];

		[self setupProgressIndicatorWindow];
	}
}

- (void)handleEvent:(OTRKitSMPEvent)event progress:(double)progress question:(NSString *)question
{
	[super handleEvent:event progress:progress question:question];

	if (event == OTRKitSMPEventAskForAnswer || event == OTRKitSMPEventAskForSecret) {
		[self setAuthenticationMethod:event];

		[self authenticateUserWithQuestion:question];
	} else if (event == OTRKitSMPEventAbort) {
		if ([[self authenticationProgressWindow] isVisible] == NO) {
			[self presentRemoteUserAbortedRequestDialog];
		}
	}
}

- (void)authenticateUserWithQuestion:(NSString *)question
{
	/* Get the visible portion of the remote user's name. */
	NSString *remoteUsername = [[OTRKit sharedInstance] leftPortionOfAccountName:[self cachedUsername]];

	/* Format several text fields with the user's name. */
	[self formatTextField:[self authenticationHostWindowTitleTextField] withUsername:remoteUsername];
	[self formatTextField:[self authenticationHostWindowDescriptionTextField] withUsername:remoteUsername];

	if ([self authenticationMethod] == OTRKitSMPEventAskForSecret) {
		[self formatTextField:[self sharedSecretDescriptionTextField] withUsername:remoteUsername];
	} else if ([self authenticationMethod] == OTRKitSMPEventAskForAnswer) {
		if (question) {
			[self formatTextField:[self questionAndAnswerDescriptionTextField] withUsername:remoteUsername];
		}

		[[self questionAndAnswerQuestionTextField] setStringValue:question];
	}

	/* Bring the trust dialog forward. */
	[self updateButtonEnabledState];

	[self bringHostWindowForward];
}

@end

#pragma mark -
#pragma mark OTRKitAuthenticationDialogOutgoing Implementation

@implementation OTRKitAuthenticationDialogOutgoing

- (instancetype)init
{
	if ((self = [super init])) {
		[[NSBundle bundleForClass:[self class]] loadNibNamed:@"OTRKitAuthenticationDialogOutgoing" owner:self topLevelObjects:nil];

		return self;
	}

	return nil;
}

- (void)cancelAuthentication:(id)sender
{
	[self teardownDialog];
}

- (void)performAuthentication:(id)sender
{
	/* Check the message state for this user. */
	OTRKitMessageState messageState = [[OTRKit sharedInstance] messageStateForUsername:[self cachedUsername]
																		   accountName:[self cachedAccountName]
																			  protocol:[self cachedProtocol]];

	if (messageState == OTRKitMessageStateFinished ||
		messageState == OTRKitMessageStatePlaintext)
	{
		[self presentPrivateConversationIsNotActiveAlert];

		return; // Cancel operation...
	}

	/* Start a negoation depending on which method was selected. */
	if ([self authenticationMethod] == OTRKitSMPEventNone)
	{
		BOOL isVerified = ([[self fingerprintIsVerifiedUserCheck] state] == NSOnState);

		[self markUserVerified:isVerified];

		[self teardownDialog];
	}
	else if ([self authenticationMethod] == OTRKitSMPEventAskForAnswer)
	{
		NSString *question = [[self questionAndAnswerQuestionTextField] stringValue];
		NSString *answer = [[self questionAndAnswerAnswerTextField] stringValue];

		[[OTRKit sharedInstance] initiateSMPForUsername:[self cachedUsername]
											accountName:[self cachedAccountName]
											   protocol:[self cachedProtocol]
											   question:question
												 secret:answer];

		[self setupProgressIndicatorWindow];
	}
	else if ([self authenticationMethod] == OTRKitSMPEventAskForSecret)
	{
		NSString *secret = [[self sharedSecretAnswerTextField] stringValue];

		[[OTRKit sharedInstance] initiateSMPForUsername:[self cachedUsername]
											accountName:[self cachedAccountName]
											   protocol:[self cachedProtocol]
												 secret:secret];

		[self setupProgressIndicatorWindow];
	}
}

- (void)authenticationMethodChanged:(id)sender
{
	/* Change to a different authentication method. */
	NSInteger selectedItem = [[self authenticationMethodSelectionPopupButton] selectedTag];

	if (selectedItem == 0) {
		[self setAuthenticationMethod:OTRKitSMPEventAskForAnswer];
	} else if (selectedItem == 1) {
		[self setAuthenticationMethod:OTRKitSMPEventAskForSecret];
	} else if (selectedItem == 2) {
		[self setAuthenticationMethod:OTRKitSMPEventNone];
	}

	[self updateButtonEnabledState];
}

- (void)updateProgressIndicatorButtonsWithEvent:(OTRKitSMPEvent)event
{
	[super updateProgressIndicatorButtonsWithEvent:event];

	if (event == OTRKitSMPEventSuccess) {
		[self markUserVerified:YES]; // Mark user as trusted.
	} else if (event == OTRKitSMPEventFailure) {
		[self markUserVerified:NO]; // Mark user as trusted.
	}
}

- (void)showFingerprintConfirmationForTheirHash
{
	NSString *remoteUsername = [[OTRKit sharedInstance] leftPortionOfAccountName:[self cachedUsername]];

	NSString *messageText = [self localizedString:@"00012[1]"];

	NSString *descriptionText = [self localizedString:@"00012[2]", remoteUsername];

	NSArray *alertButtons = @[[self localizedString:@"00012[3]"],
							  [self localizedString:@"00012[4]"]];

	[self presentAlert:messageText
	   informativeText:descriptionText
			   buttons:alertButtons
		didEndSelector:@selector(showFingerprintConfirmationForHashAlertDidEnd:returnCode:contextInfo:)];
}

- (void)showFingerprintConfirmationForHashAlertDidEnd:(NSAlert *)alert returnCode:(NSInteger)returnCode contextInfo:(void *)contextInfo
{
	dispatch_async(dispatch_get_main_queue(), ^{
		if (returnCode == NSAlertFirstButtonReturn) {
			[self authenticateUser];
		} else if (returnCode == NSAlertSecondButtonReturn) {
			[self teardownDialog];
		}
	});
}

- (void)authenticateUser
{
	/* Reset state just to be safe. */
	[self setLastEvent:OTRKitSMPEventNone];

	/* Set default content view which is Question & Answer */
	[self setAuthenticationMethod:OTRKitSMPEventAskForAnswer];

	/* Get the visible portion of the remote user's name. */
	NSString *remoteUsername = [[OTRKit sharedInstance] leftPortionOfAccountName:[self cachedUsername]];
	NSString *localUsername = [[OTRKit sharedInstance] leftPortionOfAccountName:[self cachedAccountName]];

	/* Format several text fields with the user's name. */
	[self formatTextField:[self fingerprintLocalUserLabelTextField] withUsername:localUsername];
	[self formatTextField:[self fingerprintRemoteUserLabelTextField] withUsername:remoteUsername];

	[self formatTextField:[self authenticationHostWindowTitleTextField] withUsername:remoteUsername];

	/* Gather existing fingerprint information. */
 	NSString *localFingerprint = [[OTRKit sharedInstance] fingerprintForAccountName:[self cachedAccountName]
																		   protocol:[self cachedProtocol]];

	NSString *remoteFingerprint = [[OTRKit sharedInstance] activeFingerprintForUsername:[self cachedUsername]
																			accountName:[self cachedAccountName]
																			   protocol:[self cachedProtocol]];

	/* Determine whether the user's fingerprint is already trusted. */
	BOOL remoteFingerprintTrusted = [[OTRKit sharedInstance] activeFingerprintIsVerifiedForUsername:[self cachedUsername]
																						accountName:[self cachedAccountName]
																						   protocol:[self cachedProtocol]];

	/* Populate default values. */
	[[self fingerprintLocalUserValueTextField] setStringValue:localFingerprint];
	[[self fingerprintRemoteUserValueTextField] setStringValue:remoteFingerprint];

	[[self fingerprintIsVerifiedUserCheck] setState:remoteFingerprintTrusted];

	/* Bring the trust dialog forward. */
	[self updateButtonEnabledState];

	[self bringHostWindowForward];
}

@end
#pragma clang diagnostic pop
