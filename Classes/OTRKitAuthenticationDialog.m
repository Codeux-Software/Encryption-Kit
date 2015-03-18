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

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wincomplete-implementation"

#pragma mark -
#pragma mark OTRKitAuthenticationDialog Implementation

@implementation OTRKitAuthenticationDialog

+ (void)requestAuthenticationForUsername:(NSString *)username accountName:(NSString *)accountName protocol:(NSString *)protocol callback:(OTRKitAuthenticationDialogCallbackBlock)callbackBlock
{
	NSParameterAssert(username != nil);
	NSParameterAssert(accountName != nil);
	NSParameterAssert(protocol != nil);

	OTRKitAuthenticationDialog *openDialogs = [[OTRKitAuthenticationDialogWindowManager sharedManager] dialogForUsername:username
																											 accountName:accountName
																												protocol:protocol];

	if (openDialogs) {
		LogToConsole(@"Tried to open a dialog when one was already open.");
	} else {
		OTRKitAuthenticationDialogOutgoing *outgoingRequest = [OTRKitAuthenticationDialogOutgoing new];

		[outgoingRequest setIsIncomingRequest:NO];

		[outgoingRequest setCachedUsername:username];
		[outgoingRequest setCachedAccountName:accountName];
		[outgoingRequest setCachedProtocol:protocol];

		[outgoingRequest setCallbackBlock:callbackBlock];

		[[OTRKitAuthenticationDialogWindowManager sharedManager] addDialog:outgoingRequest];

		[outgoingRequest authenticateUser];
	}
}

+ (void)handleAuthenticationRequest:(OTRKitSMPEvent)event progress:(double)progress question:(NSString *)question username:(NSString *)username accountName:(NSString *)accountName protocol:(NSString *)protocol
{
	NSParameterAssert(username != nil);
	NSParameterAssert(accountName != nil);
	NSParameterAssert(protocol != nil);

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
			openDialogs = [OTRKitAuthenticationDialogOutgoing new];

			[openDialogs setIsIncomingRequest:YES];

			[openDialogs setCachedUsername:username];
			[openDialogs setCachedAccountName:accountName];
			[openDialogs setCachedProtocol:protocol];

			[[OTRKitAuthenticationDialogWindowManager sharedManager] addDialog:openDialogs];
		}
	}

	[openDialogs handleEvent:event progress:progress question:question];
}

+ (void)showFingerprintConfirmationForTheirHash:(NSString *)theirHash ourHash:(NSString *)ourHash username:(NSString *)username accountName:(NSString *)accountName protocol:(NSString *)protocol callback:(OTRKitAuthenticationDialogCallbackBlock)callbackBlock
{
	NSParameterAssert(username != nil);
	NSParameterAssert(accountName != nil);
	NSParameterAssert(protocol != nil);

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

		[incomingRequest setCallbackBlock:callbackBlock];

		[[OTRKitAuthenticationDialogWindowManager sharedManager] addDialog:incomingRequest];

		[incomingRequest showFingerprintConfirmationForTheirHash:theirHash ourHash:ourHash];
	}
}

+ (void)cancelRequestForUsername:(NSString *)username accountName:(NSString *)accountName protocol:(NSString *)protocol
{
	NSParameterAssert(username != nil);
	NSParameterAssert(accountName != nil);
	NSParameterAssert(protocol != nil);

	OTRKitAuthenticationDialog *openDialogs = [[OTRKitAuthenticationDialogWindowManager sharedManager] dialogForUsername:username accountName:accountName protocol:protocol];

	if ( openDialogs) {
		[openDialogs cancelRequest];
	} else {
		LogToConsole(@"Tried to cancel a request for a dialog that does not exist.");
	}
}

#pragma mark -
#pragma mark Dialog Construction

- (void)bringHostWindowForward
{
	/* Bring the host window forward if it has not been brought forward already. */
	if ([self authenticationHostWindowIsVisible] == NO) {
		[[self authenticationHostWindow] makeKeyAndOrderFront:nil];

		[self setAuthenticationHostWindowIsVisible:YES];
	}
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

	/* Update keyboard navigation (tab key) */
	[[self authenticationHostWindow] recalculateKeyViewLoop];
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

- (NSString *)localizedString:(NSString *)original
{
	/* This is a framework so we have to find the bundle related to this class. */
	return [[NSBundle bundleForClass:[self class]] localizedStringForKey:original value:original table:@"OTRKitAuthenticationDialog"];
}

- (void)presentDialogAlreadyExistsErrorAlert
{
	/* Get the visible portion of the remote user's name. */
	NSString *username = [[OTRKit sharedInstance] leftPortionOfAccountName:[self cachedUsername]];

	/* Construct error messages */
	NSString *buttonText = [self localizedString:@"00010[3]"];

	NSString *messageText = [self localizedString:@"00010[1]"];

	NSString *descriptionText = [NSString stringWithFormat:[self localizedString:@"00010[2]"], username];

	/* Construct and present alert */
	NSAlert *errorAlert = [NSAlert new];

	[errorAlert setAlertStyle:NSInformationalAlertStyle];

	[errorAlert setMessageText:messageText];
	[errorAlert setInformativeText:descriptionText];

	[errorAlert addButtonWithTitle:buttonText];

	if ([[self authenticationHostWindow] attachedSheet]) {
		(void)[errorAlert runModal];
	} else {
		[errorAlert beginSheetModalForWindow:[self authenticationHostWindow]
							   modalDelegate:nil
							  didEndSelector:NULL
								 contextInfo:NULL];
	}
}

#pragma mark -
#pragma mark Teardown Dialog

- (void)maybeAbortOpenNegotations
{
	/* If a negotation is in progres, abort it. */
	if ([self lastEvent] == OTRKitSMPEventInProgress) {
		[[OTRKit sharedInstance] abortSMPForUsername:[self cachedUsername]
										 accountName:[self cachedAccountName]
											protocol:[self cachedProtocol]];
	}
}

- (void)markUserVerified:(BOOL)isVerified
{
	/* Inform callback as to whether the user was authenticated. */
	if ([self callbackBlock]) {
		[self callbackBlock]([self cachedUsername],
							 [self cachedAccountName],
							 [self cachedProtocol],
							 isVerified);
	}

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
	/* Tear down windows. */
	[self endProgressIndicatorWindow];

	[self closeHostWindow];

	/* Remove any reference to this dialog. */
	[[OTRKitAuthenticationDialogWindowManager sharedManager] removeDialog:self];
}

- (void)closeHostWindow
{
	/* Close the host window if visible. */
	if ([self authenticationHostWindowIsVisible]) {
		[[self authenticationHostWindow] close];

		[self setAuthenticationHostWindowIsVisible:NO];
	}
}

#pragma mark -
#pragma mark Progress Indicator

- (void)setLastEvent:(OTRKitSMPEvent)lastEvent
{
	/* Update last event and possibly progress information. */
	if (_lastEvent != lastEvent) {
		_lastEvent  = lastEvent;

		if ([self authenticationProgressWindowIsVisible]) {
			[self updateProgressIndicatorButtonsWithEvent:lastEvent];
		}
	}
}

- (void)handleEvent:(OTRKitSMPEvent)event progress:(double)progress question:(NSString *)question
{
	/* Update status information for event. */
	[self setLastEvent:event];

	/* Update progress information based on event. */
	[self updateProgressIndicatorPercentage:progress];
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
		modalDelegate:nil
	   didEndSelector:NULL
		  contextInfo:NULL];

	[self setAuthenticationProgressWindowIsVisible:YES];

	/* Fake our last event so that -maybeAbortOpenNegotations will work. */
	[self setLastEvent:OTRKitSMPEventInProgress];
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
	if ([self authenticationProgressWindowIsVisible]) {
		[[self authenticationProgressWindow] close];

		[self setAuthenticationProgressWindowIsVisible:NO];
	}
}

- (IBAction)authenticationProgressCancel:(id)sender
{
	/* Close negotation if it is open. */
	[self maybeAbortOpenNegotations];

	/* Close the progress window and bring the host window back forward. */
	[self endProgressIndicatorWindow];
}

- (IBAction)authenticationProgressOk:(id)sender
{
	/* If the last event was successful, then we can tear down the entire
	 dialog, not just the pgoress indicator, because we are done here. */
	if ([self lastEvent] == OTRKitSMPEventSuccess) {
		[self teardownDialog]; // Will close progress window for us...
	} else {
		[self endProgressIndicatorWindow];
	}
}

@end

#pragma mark -
#pragma mark OTRKitAuthenticationDialogIncoming Implementation

@implementation OTRKitAuthenticationDialogIncoming

- (void)cancelAuthentication:(id)sender
{

}

- (void)performAuthentication:(id)sender
{

}

- (void)handleEvent:(OTRKitSMPEvent)event progress:(double)progress question:(NSString *)question
{
	[super handleEvent:event progress:progress question:question];

	// Do something here...
}

- (void)updateProgressIndicatorButtonsWithEvent:(OTRKitSMPEvent)event
{
	
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
	/* Start a negoation depending on which method was selected. */
	if ([self authenticationMethod] == OTRKitSMPEventNone)
	{
		BOOL isVerified = ([[self fingerprintIsVerifiedUserCheck] state] == NSOnState);

		[self markUserVerified:isVerified];
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
	}
	else if ([self authenticationMethod] == OTRKitSMPEventAskForSecret)
	{
		NSString *secret = [[self sharedSecretAnswerTextField] stringValue];

		[[OTRKit sharedInstance] initiateSMPForUsername:[self cachedUsername]
											accountName:[self cachedAccountName]
											   protocol:[self cachedProtocol]
												 secret:secret];
	}

	[self setupProgressIndicatorWindow];
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

- (void)setAuthenticationMethod:(OTRKitSMPEvent)authenticationMethod
{
	/* Switch views when authentication method changes. */
	if (authenticationMethod == OTRKitSMPEventNone) {
		[self changeContentViewTo:[self contentViewFingerprintAuthentication]];
	} else if (authenticationMethod == OTRKitSMPEventAskForAnswer) {
		[self changeContentViewTo:[self contentViewQuestionAndAnswerAuthentication]];
	} else if (authenticationMethod == OTRKitSMPEventAskForSecret) {
		[self changeContentViewTo:[self contentViewSharedSecretAuthentication]];
	} else {
		NSAssert(NO, @"Bad authenticationMethod value");
	}

	[super setAuthenticationMethod:authenticationMethod];
}

- (void)updateProgressIndicatorButtonsWithEvent:(OTRKitSMPEvent)event
{
	[super updateProgressIndicatorButtonsWithEvent:event];

	if (event == OTRKitSMPEventSuccess) {
		[self markUserVerified:YES]; // Mark user as trusted.
	}
}

- (void)showFingerprintConfirmationForTheirHash:(NSString *)theirHash ourHash:(NSString *)ourHash from:(NSString *)messageFrom to:(NSString *)messageTo
{

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
