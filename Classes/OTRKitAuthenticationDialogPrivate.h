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

#import "OTRKitAuthenticationDialog.h"
#import "OTRKitAuthenticationDialogWindowManager.h"

#import "OTRKitFrameworkHelpers.h"

#pragma mark -
#pragma makr Headers

@interface OTRKitAuthenticationDialog ()
@property (nonatomic, copy) NSString *cachedUsername;
@property (nonatomic, copy) NSString *cachedAccountName;
@property (nonatomic, copy) NSString *cachedProtocol;
@property (nonatomic, assign) BOOL isIncomingRequest;
@property (nonatomic, assign) BOOL dialogAlreadyExistsErrorAlertIsVisible;
@property (nonatomic, assign) OTRKitSMPEvent lastEvent;
@property (nonatomic, assign) OTRKitSMPEvent authenticationMethod; // none = fingerprint, question & answer, or shared secret
@property (nonatomic, weak) NSWindow *applicationHostWindow;
@property (nonatomic, weak) IBOutlet NSView *contentView;
@property (nonatomic, weak) IBOutlet NSLayoutConstraint *contentViewHeightConstraint;
@property (nonatomic, strong) IBOutlet NSWindow *authenticationHostWindow;
@property (nonatomic, strong) IBOutlet NSWindow *authenticationProgressWindow;
@property (nonatomic, weak) IBOutlet NSTextField *authenticationProgressTitleTextField;
@property (nonatomic, weak) IBOutlet NSTextField *authenticationProgressStatusTextField;
@property (nonatomic, weak) IBOutlet NSButton *authenticationProgressOkButton;
@property (nonatomic, weak) IBOutlet NSButton *authenticationProgressCancelButton;
@property (nonatomic, weak) IBOutlet NSProgressIndicator *authenticationProgressProgressIndicator;
@property (nonatomic, strong) IBOutlet NSView *contentViewFingerprintAuthentication;
@property (nonatomic, strong) IBOutlet NSView *contentViewQuestionAndAnswerAuthentication;
@property (nonatomic, strong) IBOutlet NSView *contentViewSharedSecretAuthentication;
@property (nonatomic, weak) IBOutlet NSTextField *questionAndAnswerQuestionTextField;
@property (nonatomic, weak) IBOutlet NSTextField *questionAndAnswerAnswerTextField;
@property (nonatomic, weak) IBOutlet NSTextField *questionAndAnswerDescriptionTextField;
@property (nonatomic, weak) IBOutlet NSTextField *sharedSecretAnswerTextField;
@property (nonatomic, weak) IBOutlet NSTextField *sharedSecretDescriptionTextField;
@property (nonatomic, weak) IBOutlet NSTextField *fingerprintLocalUserLabelTextField;
@property (nonatomic, weak) IBOutlet NSTextField *fingerprintLocalUserValueTextField;
@property (nonatomic, weak) IBOutlet NSTextField *fingerprintRemoteUserLabelTextField;
@property (nonatomic, weak) IBOutlet NSTextField *fingerprintRemoteUserValueTextField;
@property (nonatomic, weak) IBOutlet NSTextField *fingerprintDescriptionTextField;
@property (nonatomic, weak) IBOutlet NSButton *authenticationHostWindowCancelButton;
@property (nonatomic, weak) IBOutlet NSButton *authenticationHostWindowAuthenticateButton;
@property (nonatomic, weak) IBOutlet NSTextField *authenticationHostWindowTitleTextField;
@property (nonatomic, weak) IBOutlet NSTextField *authenticationHostWindowDescriptionTextField;

- (IBAction)cancelAuthentication:(id)sender;
- (IBAction)performAuthentication:(id)sender;

- (IBAction)authenticationProgressCancel:(id)sender;
- (IBAction)authenticationProgressOk:(id)sender;

- (void)teardownDialog;

- (void)changeContentViewTo:(NSView *)contentView;

- (void)handleEvent:(OTRKitSMPEvent)event progress:(double)progress question:(NSString *)question;

- (void)updateProgressIndicatorButtonsWithEvent:(OTRKitSMPEvent)event;
@end

#pragma mark -

@interface OTRKitAuthenticationDialogIncoming : OTRKitAuthenticationDialog
@end

#pragma mark -

@interface OTRKitAuthenticationDialogOutgoing : OTRKitAuthenticationDialog <NSTextFieldDelegate>
@property (nonatomic, weak) IBOutlet NSPopUpButton *authenticationMethodSelectionPopupButton;
@property (nonatomic, weak) IBOutlet NSButton *fingerprintIsVerifiedUserCheck;

- (void)authenticateUser;

- (void)showFingerprintConfirmationForTheirHash;

- (IBAction)authenticationMethodChanged:(id)sender;
@end
