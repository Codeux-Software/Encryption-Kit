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

#import "OTRKitAuthenticationDialogWindowManager.h"
#import "OTRKitAuthenticationDialogPrivate.h"

@interface OTRKitAuthenticationDialogWindowManager ()
@property (nonatomic, strong) NSMutableDictionary *openDialogs;
@end

@implementation OTRKitAuthenticationDialogWindowManager

+ (OTRKitAuthenticationDialogWindowManager *)sharedManager
{
	static id sharedSelf = nil;

	static dispatch_once_t onceToken;

	dispatch_once(&onceToken, ^{
		 sharedSelf = [OTRKitAuthenticationDialogWindowManager new];

		[sharedSelf setOpenDialogs:[NSMutableDictionary dictionary]];
	});

	return sharedSelf;
}

- (NSArray *)allDialogs
{
	if ([NSThread isMainThread] == NO) {
		NSAssert(NO, @"Do not invoke this method from anywhere except the main thread.");
	}

	NSMutableArray *allObjects = [NSMutableArray array];

	[[self openDialogs] enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
		[allObjects addObject:obj];
	}];

	return allObjects;
}

- (void)addDialog:(OTRKitAuthenticationDialog *)dialog
{
	CheckParamaterForNilValue(dialog)

	if ([NSThread isMainThread] == NO) {
		NSAssert(NO, @"Do not invoke this method from anywhere except the main thread.");
	}

	NSString *dictKey = [self storageDictionaryKeyForUsername:[dialog cachedUsername]
												  accountName:[dialog cachedAccountName]
													 protocol:[dialog cachedProtocol]
													  isStale:NO];

	if ([self openDialogs][dictKey] == nil) {
		[self openDialogs][dictKey] = dialog;
	}
}

- (void)removeDialog:(OTRKitAuthenticationDialog *)dialog
{
	CheckParamaterForNilValue(dialog)

	if ([NSThread isMainThread] == NO) {
		NSAssert(NO, @"Do not invoke this method from anywhere except the main thread.");
	}

	__block NSString *dictKey = nil;

	[[self openDialogs] enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
		if (obj == dialog) {
			dictKey = key;
		}
	}];

	if (dictKey) {
		[[self openDialogs] removeObjectForKey:dictKey];
	}
}

- (void)markDialogAsStale:(OTRKitAuthenticationDialog *)dialog
{
	CheckParamaterForNilValue(dialog)

	if ([NSThread isMainThread] == NO) {
		NSAssert(NO, @"Do not invoke this method from anywhere except the main thread.");
	}

	NSString *dictKeyNotStale = [self storageDictionaryKeyForUsername:[dialog cachedUsername]
														  accountName:[dialog cachedAccountName]
															 protocol:[dialog cachedProtocol]
																	  isStale:NO];

	id _dialog = [self openDialogs][dictKeyNotStale];

	if (_dialog) {
		[[self openDialogs] removeObjectForKey:dictKeyNotStale];

		NSString *dictKeyIsStale = [self storageDictionaryKeyForUsername:[dialog cachedUsername]
															 accountName:[dialog cachedAccountName]
																protocol:[dialog cachedProtocol]
																 isStale:YES];

		[self openDialogs][dictKeyIsStale] = _dialog;
	}
}

- (OTRKitAuthenticationDialog *)dialogForUsername:(NSString *)username accountName:(NSString *)accountName protocol:(NSString *)protocol
{
	CheckParamaterForNilValueR(username, nil)
	CheckParamaterForNilValueR(accountName, nil)
	CheckParamaterForNilValueR(protocol, nil)

	if ([NSThread isMainThread] == NO) {
		NSAssert(NO, @"Do not invoke this method from anywhere except the main thread.");
	}

	NSString *dictKey = [self storageDictionaryKeyForUsername:username
												  accountName:accountName
													 protocol:protocol
													  isStale:NO];

	return [self openDialogs][dictKey];
}

- (NSString *)storageDictionaryKeyForUsername:(NSString *)username accountName:(NSString *)accountName protocol:(NSString *)protocol isStale:(BOOL)isStale
{
	CheckParamaterForNilValueR(username, nil)
	CheckParamaterForNilValueR(accountName, nil)
	CheckParamaterForNilValueR(protocol, nil)

	/* Stale dialogs are those that are still kept a reference to, but will not be returned
	 if looked up for. Stale dialogs are stored with a random key. We are able to remove them
	 by enumerating all open dialogs when it is time. */
	if (isStale) {
		NSString *randomID = [[NSUUID UUID] UUIDString];

		return [NSString stringWithFormat:@"%@ <-> %@ <-> %@ <-> %@", username, accountName, protocol, randomID];
	} else {
		return [NSString stringWithFormat:@"%@ <-> %@ <-> %@", username, accountName, protocol, isStale];
	}
}

@end
