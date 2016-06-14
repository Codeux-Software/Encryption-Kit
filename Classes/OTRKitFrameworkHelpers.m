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

#import "OTRKitFrameworkHelpers.h"

#include <objc/message.h>

@interface OTRKitAlertDialogContextObject : NSObject
@property (nonatomic, strong) id contextInfo;
@property (nonatomic, copy) OTRKitAlertDialogCompletionBlock completionBlock;
@end

@implementation OTRKitFrameworkHelpers

+ (NSString *)localizedString:(NSString *)original inTable:(NSString *)inTable, ...
{
	va_list arguments;
	va_start(arguments, inTable);

	NSString *formattedString = [OTRKitFrameworkHelpers localizedString:original inTable:inTable arguments:arguments];

	va_end(arguments);

	return formattedString;
}

+ (NSString *)localizedString:(NSString *)original inTable:(NSString *)inTable arguments:(va_list)arguments
{
	NSBundle *selfBundle = CurrentBundle();

	NSString *localeString = [selfBundle localizedStringForKey:original value:original table:inTable];

	NSString *formattedString = [[NSString alloc] initWithFormat:localeString arguments:arguments];

	return formattedString;
}

+ (NSWindow *)_deepestSheetOfWindow:(NSWindow *)window
{
	/* Recursively scan all attached sheets until we find a window without one. */
	NSWindow *attachedSheet = [window attachedSheet];

	if (attachedSheet) {
		return [OTRKitFrameworkHelpers _deepestSheetOfWindow:attachedSheet];
	} else {
		return window;
	}
}

+ (void)presentAlertInWindow:(NSWindow *)hostWindow messageText:(NSString *)messageText informativeText:(NSString *)informativeText buttons:(NSArray<NSString *> *)buttons contextInfo:(id)contextInfo completionBlock:(OTRKitAlertDialogCompletionBlock)completionBlock
{
	/* Construct alert */
	NSAlert *errorAlert = [NSAlert new];

	[errorAlert setAlertStyle:NSInformationalAlertStyle];

	[errorAlert setMessageText:messageText];
	[errorAlert setInformativeText:informativeText];

	for (NSString *button in buttons) {
		[errorAlert addButtonWithTitle:button];
	}

	/* Attach the sheet to the highest window */
	OTRKitAlertDialogContextObject *contextObject = nil;

	if (contextInfo || completionBlock) {
		contextObject = [OTRKitAlertDialogContextObject new];

		[contextObject setContextInfo:contextInfo];

		[contextObject setCompletionBlock:completionBlock];
	}

	if (hostWindow) {
		hostWindow = [OTRKitFrameworkHelpers _deepestSheetOfWindow:hostWindow];
	}

	if (hostWindow) {
		void *contextObjectRef = NULL;

		if (contextObject) {
			contextObjectRef = (void *)CFBridgingRetain(contextObject);
		}

		[errorAlert beginSheetModalForWindow:hostWindow
							   modalDelegate:[OTRKitFrameworkHelpers class]
							  didEndSelector:@selector(_alertDialogSheetDidEnd:returnCode:contextInfo:)
								 contextInfo:contextObjectRef];
	} else {
		NSModalResponse returnCode = [errorAlert runModal];

		if (contextObject) {
			[OTRKitFrameworkHelpers _alertDialogDidEnd:returnCode
										 contextObject:contextObject];
		}
	}
}

+ (void)_alertDialogSheetDidEnd:(NSAlert *)alert returnCode:(NSInteger)returnCode contextInfo:(void *)contextInfo
{
	if (contextInfo) {
		OTRKitAlertDialogContextObject *contextObject = (OTRKitAlertDialogContextObject *)CFBridgingRelease(contextInfo);

		[OTRKitFrameworkHelpers _alertDialogDidEnd:returnCode contextObject:contextObject];
	}
}

+ (void)_alertDialogDidEnd:(NSInteger)returnCode contextObject:(OTRKitAlertDialogContextObject *)contextObject
{
	id contextInfo = [contextObject contextInfo];

	OTRKitAlertDialogCompletionBlock completionBlock = [contextObject completionBlock];

	if (completionBlock) {
		completionBlock(returnCode, contextInfo);
	}
}

@end

@implementation OTRKitAlertDialogContextObject
@end
