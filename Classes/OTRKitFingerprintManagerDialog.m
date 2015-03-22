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

#import "OTRKitFingerprintManagerDialogPrivate.h"

@implementation OTRKitFingerprintManagerDialog

#pragma mark -
#pragma mark Public Methods

- (instancetype)init
{
	if ((self = [super init])) {
		[[NSBundle bundleForClass:[self class]] loadNibNamed:@"OTRKitFingerprintManagerDialog" owner:self topLevelObjects:nil];

		[self prepareInitialState];

		return self;
	}

	return nil;
}

- (void)dealloc
{
	[self setDelegate:nil];
}

- (void)prepareInitialState
{
	[self populateFingerprintCache];

	[self updateButtonsEnabledState];

	[[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(applicationWillTerminateNotification:) name:OTRKitPrepareForApplicationTerminationNotification object:nil];

	[[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(noteFingerprintsChanged:) name:OTRKitListOfFingerprintsDidChangeNotification object:nil];
	[[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(noteFingerprintsChanged:) name:OTRKitMessageStateDidChangeNotification object:nil];
}

- (void)open
{
	[self open:nil];
}

- (void)open:(NSWindow *)hostWindow
{
	if ([self isStale]) {
		NSAssert(NO, @"Cannot opent the dialog because it is marked as stale.");
	}

	if (hostWindow) {
		if ([[self fingerprintManagerWindow] isSheet] == NO) {
			[NSApp beginSheet:[self fingerprintManagerWindow]
			   modalForWindow:hostWindow
				modalDelegate:self
			   didEndSelector:@selector(didEndSheet:returnCode:contextInfo:)
				  contextInfo:NULL];
		}
	} else {
		[[self fingerprintManagerWindow] makeKeyAndOrderFront:nil];
	}
}

- (void)didEndSheet:(NSWindow *)sheet returnCode:(NSInteger)returnCode contextInfo:(void *)contextInfo
{
	[sheet close];

	[self closeStepTwo];
}

- (void)close
{
	if ([self isStale] == NO) {
		if ([[self fingerprintManagerWindow] isSheet]) {
			[NSApp endSheet:[self fingerprintManagerWindow]];
		} else {
			if ([[self fingerprintManagerWindow] isVisible]) {
				[[self fingerprintManagerWindow] close];

				[self closeStepTwo];
			}
		}
	}
}

- (void)closeStepTwo
{
	[self setIsStale:YES];

	[[NSNotificationCenter defaultCenter] removeObserver:self];

	if ( [self delegate]) {
		[[self delegate] otrKitFingerprintManagerDialogDidClose:self];
	}
}

- (IBAction)closeDialog:(id)sender
{
	[self close];
}

- (void)applicationWillTerminateNotification:(NSNotification *)notification
{
	[self close];
}

#pragma mark -
#pragma mark Table View

- (void)noteFingerprintsChanged:(NSNotification *)notification
{
	[self populateFingerprintCache];

	[self reloadTable];
}

- (void)populateFingerprintCache
{
	NSArray *fingerprints = [[OTRKit sharedInstance] requestAllFingerprints];

	if (fingerprints == nil) {
		[self setCachedListOfFingerprints:@[]];
	} else {
		[self setCachedListOfFingerprints:fingerprints];
	}
}

- (void)reloadTable
{
	NSInteger currentSelection = [self tableViewSelectedRow];

	[[self fingerprintListTable] reloadData];

	if (currentSelection > (-1)) {
		if ([[self fingerprintListTable] numberOfRows] > currentSelection) {
			[[self fingerprintListTable] selectRowIndexes:[NSIndexSet indexSetWithIndex:currentSelection] byExtendingSelection:NO];
		} else {
			[self updateButtonsEnabledState];
		}
	}
}

- (NSInteger)tableViewSelectedRow
{
	return [[self fingerprintListTable] selectedRow];
}

- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView
{
	return [[self cachedListOfFingerprints] count];
}

- (NSView *)tableView:(NSTableView *)tableView viewForTableColumn:(NSTableColumn *)tableColumn row:(NSInteger)row
{
	/* Make the view in which the data will be populated. */
	OTRKitFingerprintManagerDialogTableCellView *madeView = (id)[tableView makeViewWithIdentifier:[tableColumn identifier] owner:self];

	/* Begin populating individual data sections. */
	OTRKitConcreteObject *rowEntryData = [[self cachedListOfFingerprints] objectAtIndex:row];

	/* Populate username value */
	if ([[tableColumn identifier] isEqual:@"username"]) {
		NSString *newValue = [[OTRKit sharedInstance] leftPortionOfAccountName:[rowEntryData username]];

		[[madeView textField] setStringValue:newValue];
	}

	/* Populate account name value */
	else if ([[tableColumn identifier] isEqual:@"accountName"])
	{
		NSString *newValue = [[OTRKit sharedInstance] leftPortionOfAccountName:[rowEntryData accountName]];

		[[madeView textField] setStringValue:newValue];
	}

	/* Populate status value */
	else if ([[tableColumn identifier] isEqual:@"status"])
	{
		BOOL isInUse = [self isFingerprintActiveForObject:rowEntryData];

		if (isInUse) {
			[[madeView textField] setStringValue:[self localizedString:@"00001[2]"]];
		} else {
			[[madeView textField] setStringValue:[self localizedString:@"00001[1]"]];
		}
	}

	/* Populate trust value */
	else if ([[tableColumn identifier] isEqual:@"trusted"])
	{
		BOOL isTrusted = [rowEntryData fingerprintIsTrusted];

		if (isTrusted) {
			[[madeView viewCheckbox] setState:NSOnState];
		} else {
			[[madeView viewCheckbox] setState:NSOffState];
		}

		[[madeView viewCheckbox] setTag:row];
	}

	/* Populate fingerprint value */
	else if ([[tableColumn identifier] isEqual:@"fingerprint"])
	{
		NSString *newValue = [rowEntryData fingerprintString];

		[[madeView textField] setStringValue:newValue];
	}

	return madeView;
}

- (NSString *)localizedString:(NSString *)original, ...
{
	va_list args;
	va_start(args, original);

	NSString *formattedString = [OTRKitFrameworkHelpers localizedString:original inTable:@"OTRKitFingerprintManagerDialog" arguments:args];

	va_end(args);

	return formattedString;
}

- (void)tableViewSelectionDidChange:(NSNotification *)notification
{
	[self updateButtonsEnabledState];
}

- (void)updateButtonsEnabledState
{
	if ([self tableViewSelectedRow] == (-1))
	{
		[[self buttonFingerprintForget] setEnabled:NO];

		[[self buttonFingerprintStopConversation] setHidden:YES];
	}
	else
	{
		OTRKitConcreteObject *dataObject  = [[self cachedListOfFingerprints] objectAtIndex:[self tableViewSelectedRow]];

		BOOL isFingerprintActive = [self isFingerprintActiveForObject:dataObject];

		BOOL buttonCondition = (isFingerprintActive == NO);

		[[self buttonFingerprintForget] setEnabled:buttonCondition];

		[[self buttonFingerprintStopConversation] setHidden:buttonCondition];
	}
}

- (BOOL)isFingerprintActiveForObject:(OTRKitConcreteObject *)dataObject
{
	NSString *activeFingerprint = [[OTRKit sharedInstance] activeFingerprintForUsername:[dataObject username]
																			accountName:[dataObject accountName]
																			   protocol:[dataObject protocol]];

	return ([[dataObject fingerprintString] isEqual:activeFingerprint]);
}

#pragma mark -
#pragma mark Actions

- (IBAction)fingerprintStopConversation:(id)sender
{
	OTRKitConcreteObject *dataObject  = [[self cachedListOfFingerprints] objectAtIndex:[self tableViewSelectedRow]];

	[[OTRKit sharedInstance] disableEncryptionWithUsername:[dataObject username]
											   accountName:[dataObject accountName]
												  protocol:[dataObject protocol]];
}

- (IBAction)fingerprintForget:(id)sender
{
	OTRKitConcreteObject *dataObject  = [[self cachedListOfFingerprints] objectAtIndex:[self tableViewSelectedRow]];

	[[OTRKit sharedInstance] deleteFingerprintWithConcreteObject:dataObject];
}

- (IBAction)fingerprintModifyTrust:(id)sender
{
	OTRKitConcreteObject *dataObject  = [[self cachedListOfFingerprints] objectAtIndex:[sender tag]];

	BOOL isVerified = ([sender state] == NSOnState);

	[[OTRKit sharedInstance] setFingerprintVerificationForConcreteObject:dataObject
																verified:isVerified];
}

@end

#pragma mark -
#pragma mark Table View Helpers

@implementation OTRKitFingerprintManagerDialogTableCellView
@end
