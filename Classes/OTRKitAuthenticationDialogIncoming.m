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

@implementation OTRKitAuthenticationDialogIncoming

- (void)_prepareInitialState
{
	[CurrentBundle() loadNibNamed:@"OTRKitAuthenticationDialogIncoming" owner:self topLevelObjects:nil];

	[super _prepareInitialState];
}

- (BOOL)isIncomingRequest
{
	return YES;
}

- (void)_cancelAuthentication:(id)sender
{
	[self _cancelRequest];
}

- (void)_performAuthentication:(id)sender
{
	/* Check the message state for this user. */
	OTRKitMessageState messageState = [[OTRKit sharedInstance] messageStateForUsername:self.cachedUsername
																		   accountName:self.cachedAccountName
																			  protocol:self.cachedProtocol];

	if (messageState == OTRKitMessageStateFinished ||
		messageState == OTRKitMessageStatePlaintext)
	{
		[self _presentPrivateConversationIsNotActiveAlert];

		return; // Cancel operation...
	}

	/* Start a negotiation depending on which method was selected. */
	NSString *secretAnswer = nil;

	if (self.authenticationMethod == OTRKitSMPEventAskForAnswer) {
		secretAnswer = [self.questionAndAnswerAnswerTextField stringValue];
	} else if (self.authenticationMethod == OTRKitSMPEventAskForSecret) {
		secretAnswer = [self.sharedSecretAnswerTextField stringValue];
	}

	if (secretAnswer) {
		[[OTRKit sharedInstance] respondToSMPForUsername:self.cachedUsername
											 accountName:self.cachedAccountName
												protocol:self.cachedProtocol
												  secret:secretAnswer];

		[self _setupProgressIndicatorWindow];
	}
}

- (void)_handleEvent:(OTRKitSMPEvent)event progress:(double)progress question:(NSString *)question
{
	[super _handleEvent:event progress:progress question:question];

	if (event == OTRKitSMPEventAskForAnswer || event == OTRKitSMPEventAskForSecret)
	{
		self.authenticationMethod = event;

		[self _authenticateUserWithQuestion:question];
	}
	else if (event == OTRKitSMPEventAbort)
	{
		if ([self _progressIndicatorWindowIsVisible] == NO) {
			[self _presentRemoteUserAbortedAuthenticationRequestAlert];
		}
	}
}

- (void)_authenticateUserWithQuestion:(NSString *)question
{
	/* Get the visible portion of the remote user's name. */
	NSString *remoteUsername = [[OTRKit sharedInstance] leftPortionOfAccountName:self.cachedUsername];

	/* Format several text fields with the user's name. */
	[self _formatTextField:self.authenticationHostWindowTitleTextField withUsername:remoteUsername];
	[self _formatTextField:self.authenticationHostWindowDescriptionTextField withUsername:remoteUsername];

	if (self.authenticationMethod == OTRKitSMPEventAskForSecret) {
		[self _formatTextField:self.sharedSecretDescriptionTextField withUsername:remoteUsername];
	} else if (self.authenticationMethod == OTRKitSMPEventAskForAnswer) {
		[self _formatTextField:self.questionAndAnswerDescriptionTextField withUsername:remoteUsername];

		[self.questionAndAnswerQuestionTextField setStringValue:question];
	}

	/* Bring the trust dialog forward */
	[self _updateButtonEnabledState];

	[self _bringHostWindowForward];
}

@end
