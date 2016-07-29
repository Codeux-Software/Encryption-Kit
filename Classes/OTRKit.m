/*
 * OTRKit.m
 * OTRKit
 *
 * Created by Chris Ballinger on 9/4/11.
 * Copyright (c) 2012 Chris Ballinger. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * Neither the name of the project's author nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#import "OTRKitPrivate.h"

static NSString * const kOTRKitPrivateKeyFileName		= @"OTR-PrivateKey";
static NSString * const kOTRKitFingerprintsFileName		= @"OTR-Fingerprints";
static NSString * const kOTRKitInstanceTagsFileName		= @"OTR-InstanceTags";

static NSString * const kOTRKitErrorDomain				= @"org.chatsecure.OTRKit";

NSString * const OTRKitListOfFingerprintsDidChangeNotification	= @"OTRKitListOfFingerprintsDidChangeNotification";
NSString * const OTRKitMessageStateDidChangeNotification		= @"OTRKitMessageStateDidChangeNotification";

@implementation OTRKit

#pragma mark -
#pragma mark libotr ui_ops callback functions

static OtrlPolicy policy_cb(void *opdata, ConnContext *context)
{
	OTRKit *otrKit = [OTRKit sharedInstance];

	return [otrKit _otrlPolicy];
}

static void create_privkey_cb(void *opdata, const char *accountname, const char *protocol)
{
	OTRKit *otrKit = [OTRKit sharedInstance];

	/* Inform delegate of intent to create key */
	NSString *accountNameString = @(accountname);
	NSString *protocolString = @(protocol);

	[otrKit _performAsyncOperationOnDelegateQueue:^{
		[[otrKit delegate] otrKit:otrKit willStartGeneratingPrivateKeyForAccountName:accountNameString protocol:protocolString];
	}];

	/* Create key then inform delegate */
	void *otrKey;

	gcry_error_t generateError = otrl_privkey_generate_start([otrKit userState], accountname, protocol, &otrKey);

	NSString *path = [otrKit privateKeyPath];

	FILE *filePointer = fopen([path UTF8String], "w+b");

	if (generateError == gcry_error(GPG_ERR_NO_ERROR)) {
		otrl_privkey_generate_calculate(otrKey);

		otrl_privkey_generate_finish_FILEp([otrKit userState], otrKey, filePointer);

		[otrKit _performAsyncOperationOnDelegateQueue:^{
			[[otrKit delegate] otrKit:otrKit didFinishGeneratingPrivateKeyForAccountName:accountNameString protocol:protocolString error:nil];
		}];
	} else {
		NSError *error = [otrKit _errorForGPGError:generateError];

		[otrKit _performAsyncOperationOnDelegateQueue:^{
			[[otrKit delegate] otrKit:otrKit didFinishGeneratingPrivateKeyForAccountName:accountNameString protocol:protocolString error:error];
		}];
	}

	fclose(filePointer);
}

static int is_logged_in_cb(void *opdata, const char *accountname, const char *protocol, const char *recipient)
{
	OTRKit *otrKit = [OTRKit sharedInstance];

	if ([otrKit delegate] == nil) {
		return (-1);
	}

	__block BOOL loggedIn = NO;

	[otrKit _performSyncOperationOnDelegateQueue:^{
		loggedIn = [[otrKit delegate] otrKit:otrKit
						  isUsernameLoggedIn:@(recipient)
								 accountName:@(accountname)
									protocol:@(protocol)];
	}];

	if (loggedIn) {
		return 1;
	} else {
		return 0;
	}
}

static void inject_message_cb(void *opdata, const char *accountname, const char *protocol, const char *recipient, const char *message)
{
	OTRKit *otrKit = [OTRKit sharedInstance];

	if ([otrKit delegate] == nil) {
		return;
	}

	NSString *messageString = @(message);

	NSString *usernameString = @(recipient);
	NSString *accountNameString = @(accountname);

	NSString *protocolString = @(protocol);

	id tag = (__bridge id)(opdata);

	[otrKit _performAsyncOperationOnDelegateQueue:^{
		[[otrKit delegate] otrKit:otrKit injectMessage:messageString username:usernameString accountName:accountNameString protocol:protocolString tag:tag];
	}];
}

static void update_context_list_cb(void *opdata)
{
}

static void confirm_fingerprint_cb(void *opdata, OtrlUserState us, const char *accountname, const char *protocol, const char *username, unsigned char fingerprint[20])
{
	OTRKit *otrKit = [OTRKit sharedInstance];

	NSString *accountNameString = @(accountname);
	NSString *usernameString = @(username);

	NSString *protocolString = @(protocol);

	NSString *ourFingerprintString =
	[otrKit fingerprintForAccountName:accountNameString protocol:protocolString];

	char theirFingerprintHash[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];

	otrl_privkey_hash_to_human(theirFingerprintHash, fingerprint);

	NSString *theirFingerprintString = @(theirFingerprintHash);

	[otrKit _performAsyncOperationOnDelegateQueue:^{
		[[otrKit delegate] otrKit:otrKit showFingerprintConfirmationForTheirHash:theirFingerprintString ourHash:ourFingerprintString username:usernameString accountName:accountNameString protocol:protocolString];
	}];
}

static void write_fingerprints_cb(void *opdata)
{
	OTRKit *otrKit = [OTRKit sharedInstance];

	[otrKit _writeFingerprintsPath];
}

static void gone_secure_cb(void *opdata, ConnContext *context)
{
	OTRKit *otrKit = [OTRKit sharedInstance];

	[otrKit _updateEncryptionStatusWithContext:context];
}

/**
 *  This method is never called due to a bug in libotr 4.0.0
 */
static void gone_insecure_cb(void *opdata, ConnContext *context)
{
	OTRKit *otrKit = [OTRKit sharedInstance];

	[otrKit _updateEncryptionStatusWithContext:context];
}

static void still_secure_cb(void *opdata, ConnContext *context, int is_reply)
{
	OTRKit *otrKit = [OTRKit sharedInstance];

	[otrKit _updateEncryptionStatusWithContext:context];
}

static int max_message_size_cb(void *opdata, ConnContext *context)
{
	NSString *protocolString = @(context->protocol);

	if ([protocolString length] == 0) {
		return 0;
	}

	OTRKit *otrKit = [OTRKit sharedInstance];

	NSNumber *maxMessageSize = [otrKit protocolMaxSize][protocolString];

	if (maxMessageSize) {
		return [maxMessageSize intValue];
	}

	return 0;
}

static const char *otr_error_message_cb(void *opdata, ConnContext *context, OtrlErrorCode err_code)
{
	NSString *errorString = nil;

	switch (err_code)
	{
		case OTRL_ERRCODE_NONE:
		{
			break;
		}
		case OTRL_ERRCODE_ENCRYPTION_ERROR:
		{
			errorString = @"Error occurred encrypting message.";

			break;
		}
		case OTRL_ERRCODE_MSG_NOT_IN_PRIVATE:
		{
			if (context) {
				errorString = [NSString stringWithFormat:@"You sent encrypted data to %s, who wasn't expecting it.", context->accountname];
			}

			break;
		}
		case OTRL_ERRCODE_MSG_UNREADABLE:
		{
			errorString = @"You transmitted an unreadable encrypted message.";

			break;
		}
		case OTRL_ERRCODE_MSG_MALFORMED:
		{
			errorString = @"You transmitted a malformed data message.";

			break;
		}
	}

	return [errorString UTF8String];
}

static void otr_error_message_free_cb(void *opdata, const char *err_msg)
{
	// Leak memory here instead of crashing:
	// if (err_msg) free((char*)err_msg);
}

static void handle_smp_event_cb(void *opdata, OtrlSMPEvent smp_event, ConnContext *context, unsigned short progress_percent, char *question)
{
	OTRKit *otrKit = [OTRKit sharedInstance];

	OTRKitSMPEvent event = OTRKitSMPEventNone;

	if (context == NULL) {
		return;
	}

	BOOL abortSMP = NO;

	switch (smp_event)
	{
		case OTRL_SMPEVENT_NONE:
		{
			event = OTRKitSMPEventNone;

			break;
		}
		case OTRL_SMPEVENT_ASK_FOR_SECRET:
		{
			event = OTRKitSMPEventAskForSecret;

			break;
		}
		case OTRL_SMPEVENT_ASK_FOR_ANSWER:
		{
			event = OTRKitSMPEventAskForAnswer;

			break;
		}
		case OTRL_SMPEVENT_CHEATED:
		{
			event = OTRKitSMPEventCheated;

			abortSMP = YES;

			break;
		}
		case OTRL_SMPEVENT_IN_PROGRESS:
		{
			event = OTRKitSMPEventInProgress;

			break;
		}
		case OTRL_SMPEVENT_SUCCESS:
		{
			event = OTRKitSMPEventSuccess;

			break;
		}
		case OTRL_SMPEVENT_FAILURE:
		{
			event = OTRKitSMPEventFailure;

			break;
		}
		case OTRL_SMPEVENT_ABORT:
		{
			event = OTRKitSMPEventAbort;

			break;
		}
		case OTRL_SMPEVENT_ERROR:
		{
			event = OTRKitSMPEventError;

			abortSMP = YES;

			break;
		}
	}

	if (abortSMP) {
		otrl_message_abort_smp([otrKit userState], &ui_ops, opdata, context);
	}

	NSString *questionString = nil;

	if (question) {
		questionString = @(question);
	}

	NSString *usernameString = @(context->username);
	NSString *accountNameString = @(context->accountname);

	NSString *protocolString = @(context->protocol);

	[otrKit _performAsyncOperationOnDelegateQueue:^{
		[[otrKit delegate] otrKit:otrKit handleSMPEvent:event progress:progress_percent question:questionString username:usernameString accountName:accountNameString protocol:protocolString];
	}];
}

static void handle_msg_event_cb(void *opdata, OtrlMessageEvent msg_event, ConnContext *context, const char *message, gcry_error_t err)
{
	if (context == NULL) {
		return;
	}

	OTRKit *otrKit = [OTRKit sharedInstance];

	NSString *messageString = nil;

	if (message) {
		messageString = @(message);
	}

	NSError *error = [otrKit _errorForGPGError:err];

	OTRKitMessageEvent event = OTRKitMessageEventNone;

	switch (msg_event) {
		case OTRL_MSGEVENT_NONE:
		{
			event = OTRKitMessageEventNone;

			break;
		}
		case OTRL_MSGEVENT_ENCRYPTION_REQUIRED:
		{
			event = OTRKitMessageEventEncryptionRequired;

			break;
		}
		case OTRL_MSGEVENT_ENCRYPTION_ERROR:
		{
			event = OTRKitMessageEventEncryptionError;

			break;
		}
		case OTRL_MSGEVENT_CONNECTION_ENDED:
		{
			event = OTRKitMessageEventConnectionEnded;

			break;
		}
		case OTRL_MSGEVENT_SETUP_ERROR:
		{
			event = OTRKitMessageEventSetupError;

			break;
		}
		case OTRL_MSGEVENT_MSG_REFLECTED:
		{
			event = OTRKitMessageEventMessageReflected;

			break;
		}
		case OTRL_MSGEVENT_MSG_RESENT:
		{
			event = OTRKitMessageEventMessageResent;

			break;
		}
		case OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE:
		{
			event = OTRKitMessageEventReceivedMessageNotInPrivate;

			break;
		}
		case OTRL_MSGEVENT_RCVDMSG_UNREADABLE:
		{
			event = OTRKitMessageEventReceivedMessageUnreadable;

			break;
		}
		case OTRL_MSGEVENT_RCVDMSG_MALFORMED:
		{
			event = OTRKitMessageEventReceivedMessageMalformed;

			break;
		}
		case OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD:
		{
			event = OTRKitMessageEventLogHeartbeatReceived;

			break;
		}
		case OTRL_MSGEVENT_LOG_HEARTBEAT_SENT:
		{
			event = OTRKitMessageEventLogHeartbeatSent;

			break;
		}
		case OTRL_MSGEVENT_RCVDMSG_GENERAL_ERR:
		{
			event = OTRKitMessageEventReceivedMessageGeneralError;

			break;
		}
		case OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED:
		{
			event = OTRKitMessageEventReceivedMessageUnencrypted;

			break;
		}
		case OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED:
		{
			event = OTRKitMessageEventReceivedMessageUnrecognized;

			break;
		}
		case OTRL_MSGEVENT_RCVDMSG_FOR_OTHER_INSTANCE:
		{
			event = OTRKitMessageEventReceivedMessageForOtherInstance;

			break;
		}
	}

	NSString *usernameString = @(context->username);
	NSString *accountNameString = @(context->accountname);

	NSString *protocolString = @(context->protocol);

	id tag = (__bridge id)(opdata);

	[otrKit _performAsyncOperationOnDelegateQueue:^{
		[[otrKit delegate] otrKit:otrKit handleMessageEvent:event message:messageString username:usernameString accountName:accountNameString protocol:protocolString tag:tag error:error];
	}];
}

static void create_instag_cb(void *opdata, const char *accountname, const char *protocol)
{
	OTRKit *otrKit = [OTRKit sharedInstance];

	NSString *path = [otrKit instanceTagsPath];

	FILE *filePointer = fopen([path UTF8String], "w+b");

	otrl_instag_generate_FILEp([otrKit userState], filePointer, accountname, protocol);

	fclose(filePointer);
}

static void timer_control_cb(void *opdata, unsigned int interval)
{
	OTRKit *otrKit = [OTRKit sharedInstance];

	[otrKit _performAsyncOperationOnInternalQueue:^{
		if ( [otrKit pollTimer]) {
			[[otrKit pollTimer] invalidate];

			[otrKit setPollTimer:nil];
		}

		if (interval > 0) {
			NSTimer *pollTimer = [NSTimer scheduledTimerWithTimeInterval:interval target:otrKit selector:@selector(messagePoll:) userInfo:nil repeats:YES];

			[otrKit setPollTimer:pollTimer];
		}
	}];
}

static void received_symkey_cb(void *opdata, ConnContext *context, unsigned int use, const unsigned char *usedata, size_t usedatalen, const unsigned char *symkey)
{
	OTRKit *otrKit = [OTRKit sharedInstance];

	NSData *symmetricKey = [[NSData alloc] initWithBytes:symkey length:OTRL_EXTRAKEY_BYTES];

	NSData *useDescriptionData = [[NSData alloc] initWithBytes:usedata length:usedatalen];

	NSString *usernameString = @(context->username);
	NSString *accountNameString = @(context->accountname);

	NSString *protocolString = @(context->protocol);

	[otrKit _performAsyncOperationOnDelegateQueue:^{
		[[otrKit delegate] otrKit:otrKit receivedSymmetricKey:symmetricKey forUse:use useData:useDescriptionData username:usernameString accountName:accountNameString protocol:protocolString];
	}];
}

static OtrlMessageAppOps ui_ops = {
	policy_cb,
	create_privkey_cb,
	is_logged_in_cb,
	inject_message_cb,
	update_context_list_cb,
	confirm_fingerprint_cb,
	write_fingerprints_cb,
	gone_secure_cb,
	gone_insecure_cb,
	still_secure_cb,
	max_message_size_cb,
	NULL,                   /* account_name */
	NULL,                   /* account_name_free */
	received_symkey_cb,
	otr_error_message_cb,
	otr_error_message_free_cb,
	NULL,
	NULL,
	handle_smp_event_cb,
	handle_msg_event_cb,
	create_instag_cb,
	NULL,		    /* convert_data */
	NULL,		    /* convert_data_free */
	timer_control_cb
};

#pragma mark -
#pragma mark Initialization

+ (instancetype)sharedInstance
{
	static OTRKit *_sharedInstance = nil;

	static dispatch_once_t onceToken;

	dispatch_once(&onceToken, ^{
		_sharedInstance = [OTRKit new];
	});

	return _sharedInstance;
}

- (void)dealloc
{
	if ( self.pollTimer) {
		[self.pollTimer invalidate];
		 self.pollTimer = nil;
	}

	otrl_userstate_free(self.userState);

	self.userState = NULL;
}

- (instancetype)init
{
	if ((self = [super init])) {
		self.internalQueue = dispatch_queue_create("OTRKit Internal Queue", DISPATCH_QUEUE_SERIAL);

		IsOnInternalQueueKey = &IsOnInternalQueueKey;
		dispatch_queue_set_specific(self.internalQueue, IsOnInternalQueueKey, (void *)1, NULL);

		[self _performAsyncOperationOnInternalQueue:^{
			OTRL_INIT;

			self.accountNameSeparator = @"@";

			NSDictionary *protocolDefaults = @{@"prpl-msn":   @(1409),
											   @"prpl-icq":   @(2346),
											   @"prpl-aim":   @(2343),
											   @"prpl-yahoo": @(832),
											   @"prpl-gg":    @(1999),
											   @"prpl-irc":   @(400),
											   @"prpl-oscar": @(2343)};

			self.protocolMaxSize = protocolDefaults;

			self.userState = otrl_userstate_create();
		}];
	}

	return self;
}

- (void)setupWithDataPath:(NSString *)dataPath
{
	if (dataPath == nil || [dataPath length] == 0) {
		self.dataPath = [self documentsDirectory];
	} else {
		self.dataPath = dataPath;
	}

	BOOL isDirectory = NO;

	BOOL directoryExists =
	[[NSFileManager defaultManager] fileExistsAtPath:self.dataPath isDirectory:&isDirectory];

	if (directoryExists) {
		NSParameterAssert(isDirectory);
	} else {
		NSError *createDirectoryError = nil;

		BOOL createDirectoryResult = [[NSFileManager defaultManager] createDirectoryAtPath:self.dataPath withIntermediateDirectories:YES attributes:nil error:&createDirectoryError];

		NSAssert1(createDirectoryResult, @"Tried to create data path but failed doing so: '%@'", [createDirectoryError localizedDescription]);
	}

	[self _readLibotrConfiguration];
}

- (void)_readLibotrConfiguration
{
	[self _performAsyncOperationOnInternalQueue:^{
		[self _readPrivateKeyPath];

		[self _readFingerprintsPath];

		[self _readInstanceTagsPath];
	}];
}

- (void)setMaximumProtocolSize:(int)maxSize forProtocol:(NSString *)protocol
{
	AssertParamaterLength(protocol)

	[self _performAsyncOperationOnInternalQueue:^{
		NSMutableDictionary *protocolMaxSizeMutable = [self.protocolMaxSize mutableCopy];

		protocolMaxSizeMutable[protocol] = @(maxSize);

		self.protocolMaxSize = protocolMaxSizeMutable;
	}];
}

- (void)messagePoll:(NSTimer *)timer
{
	[self _performAsyncOperationOnInternalQueue:^{
		if (self.userState) {
			otrl_message_poll(self.userState, &ui_ops, NULL);
		} else {
			[timer invalidate];
		}
	}];
}

#pragma mark Initialization

- (void)decodeMessage:(NSString *)message username:(NSString *)username accountName:(NSString *)accountName protocol:(NSString *)protocol tag:(id)tag
{
	AssertParamaterLength(message)
	AssertParamaterLength(username)
	AssertParamaterLength(accountName)
	AssertParamaterLength(protocol)

	[self _performAsyncOperationOnInternalQueue:^{
		char *otrDecodedMessage = NULL;

		ConnContext *otrContext = [self _contextForUsername:username accountName:accountName protocol:protocol];

		OtrlTLV *otr_tlvs = NULL;

		int ignoreMessage = otrl_message_receiving(self.userState,
												   &ui_ops,
												   (__bridge void *)tag,
												   [accountName UTF8String],
												   [protocol UTF8String],
												   [username UTF8String],
												   [message UTF8String],
												   &otrDecodedMessage,
												   &otr_tlvs,
												   &otrContext,
												   NULL,
												   NULL);

		NSString *decodedMessage = nil;

		NSArray *tlvs = nil;

		if (otr_tlvs) {
			tlvs = [self _tlvArrayForTLVChain:otr_tlvs];
		}

		if (otrContext) {
			if (otrContext->msgstate == OTRL_MSGSTATE_FINISHED) {
				[self disableEncryptionWithUsername:username accountName:accountName protocol:protocol];
			}
		}

		BOOL wasEncrypted = (otrMessageType != OTRKitMessageTypeNotOTR);

		if (ignoreMessage == 0)
		{
			if (otrDecodedMessage) {
				decodedMessage = @(otrDecodedMessage);
			} else {
				decodedMessage = message; // Nothing changed...
			}

			[self _performAsyncOperationOnDelegateQueue:^{
				[self.delegate otrKit:self
					   decodedMessage:decodedMessage
						 wasEncrypted:wasEncrypted
								 tlvs:tlvs
							 username:username
						  accountName:accountName
							 protocol:protocol
								  tag:tag];
			}];
		}
		else if (tlvs)
		{
			[self _performAsyncOperationOnDelegateQueue:^{
				[self.delegate otrKit:self
					   decodedMessage:nil
						 wasEncrypted:wasEncrypted
								 tlvs:tlvs
							 username:username
						  accountName:accountName
							 protocol:protocol
								  tag:tag];
			}];
		}

		if (otrDecodedMessage) {
			otrl_message_free(otrDecodedMessage);
		}

		if (otr_tlvs) {
			otrl_tlv_free(otr_tlvs);
		}
	}];
}

- (void)encodeMessage:(NSString *)message
				 tlvs:(NSArray *)tlvs
			 username:(NSString *)username
		  accountName:(NSString *)accountName
			 protocol:(NSString *)protocol
				  tag:(id)tag
{
//	AssertParamaterLength(message)
	AssertParamaterLength(username)
	AssertParamaterLength(accountName)
	AssertParamaterLength(protocol)

	[self _performAsyncOperationOnInternalQueue:^{
		ConnContext *otrContext = [self _contextForUsername:username accountName:accountName protocol:protocol];

		/*
		 * If our policy is not oppritunistic (automatic) and we are not in an encrypted,
		 * then return unecnrypted message to delegate. This exception is made because when
		 * OTRL_POLICY_MANUAL is set, OTR discards outgoing * messages altogther.
		 *
		 * If our policy is ppritunistic (automatic) and our OTR request was rejected,
		 * then we will return unecnrypted message to delegate. OTR will refuse to do further
		 * work when the state is rejected.
		 */
		if (/* 1 */ (self.otrPolicy == OTRKitPolicyManual ||
					 self.otrPolicy == OTRKitPolicyNever) ||
			/* 2 */ (self.otrPolicy == OTRKitPolicyOpportunistic &&
					 [self _offerStateForContext:otrContext] == OTRKitOfferStateRejected))
		{
			OTRKitMessageState otrMessageState = [self _messageStateForContext:otrContext];

			if (otrMessageState == OTRKitMessageStatePlaintext) {
				[self _performAsyncOperationOnDelegateQueue:^{
					[self.delegate otrKit:self
						   encodedMessage:message
							 wasEncrypted:NO
								 username:username
							  accountName:accountName
								 protocol:protocol
									  tag:tag
									error:nil];
				}];

				return;
			}
		}

		[self _encodeMessage:message
				   inContext:otrContext
						tlvs:tlvs
					username:username
				 accountName:accountName
					protocol:protocol
						 tag:tag];
	}];
}

- (void)_encodeMessage:(NSString *)message
			 inContext:(ConnContext *)otrContext
				  tlvs:(NSArray *)tlvs
			  username:(NSString *)username
		   accountName:(NSString *)accountName
			  protocol:(NSString *)protocol
				   tag:(id)tag
{
	AssertParamaterLength(username)
	AssertParamaterLength(accountName)
	AssertParamaterLength(protocol)

	gcry_error_t otrError;

	char *otrEncodedMessage = NULL;

	// Set nil messages to empty string if TLVs are present, otherwise libotr
	// will silence the message, even though you may have meant to inject a TLV.
	NSString *messageToEncode = message;

	if (message == nil && [tlvs count] > 0) {
		messageToEncode = @"";
	}

	OtrlTLV *otr_tlvs = [self _tlvChainForTLVs:tlvs];

	otrError = otrl_message_sending(self.userState,
									 &ui_ops,
									 (__bridge void *)(tag),
									 [accountName UTF8String],
									 [protocol UTF8String],
									 [username UTF8String],
									 OTRL_INSTAG_BEST,
									 [messageToEncode UTF8String],
									 otr_tlvs,
									 &otrEncodedMessage,
									 OTRL_FRAGMENT_SEND_ALL,
									 &otrContext,
									 NULL,
									 NULL);

	if (otr_tlvs) {
		otrl_tlv_free(otr_tlvs);
	}

	BOOL wasEncrypted = NO;

	NSString *encodedMessage = nil;

	if (otrEncodedMessage) {
		encodedMessage = @(otrEncodedMessage);

		otrl_message_free(otrEncodedMessage);

		wasEncrypted = ([self typeOfMessage:encodedMessage] != OTRKitMessageTypeNotOTR);
	}

	NSError *errorString = nil;

	if (otrError != 0) {
		errorString = [self _errorForGPGError:otrError];

		encodedMessage = nil;
	}

	[self _performAsyncOperationOnDelegateQueue:^{
		[self.delegate otrKit:self
			   encodedMessage:encodedMessage
				 wasEncrypted:wasEncrypted
					 username:username
				  accountName:accountName
					 protocol:protocol
						  tag:tag
						error:errorString];
	}];
}

- (void)initiateEncryptionWithUsername:(NSString *)username
						   accountName:(NSString *)accountName
							  protocol:(NSString *)protocol
{
	ConnContext *otrContext = [self _contextForUsername:username accountName:accountName protocol:protocol];

	[self _encodeMessage:@"?OTR?" inContext:otrContext tlvs:nil username:username accountName:accountName protocol:protocol tag:nil];
}

- (void)disableEncryptionWithUsername:(NSString *)username
						  accountName:(NSString *)accountName
							 protocol:(NSString *)protocol
{
	AssertParamaterLength(username)
	AssertParamaterLength(accountName)
	AssertParamaterLength(protocol)

	[self _performAsyncOperationOnInternalQueue:^{
		otrl_message_disconnect_all_instances(self.userState, &ui_ops, NULL, [accountName UTF8String], [protocol UTF8String], [username UTF8String]);

		ConnContext *otrContext = [self _contextForUsername:username accountName:accountName protocol:protocol];

		if (otrContext) {
			[self _updateEncryptionStatusWithContext:otrContext];
		}
	}];
}

#pragma mark -
#pragma mark Helpers

- (NSError *)_errorForGPGError:(gcry_error_t)gpg_error
{
	if (gpg_error == gcry_err_code(GPG_ERR_NO_ERROR)) {
		return nil;
	}

	const char *gpg_error_string = gcry_strerror(gpg_error);
	const char *gpg_error_source = gcry_strsource(gpg_error);

	gpg_err_code_t gpg_error_code = gcry_err_code(gpg_error);

	int errorCode = gcry_err_code_to_errno(gpg_error_code);

	NSString *errorString = nil;
	NSString *errorSource = nil;

	if (gpg_error_string) {
		errorString = @(gpg_error_string);
	}

	if (gpg_error_source) {
		errorSource = @(gpg_error_source);
	}

	NSMutableString *errorDescription = [NSMutableString string];

	if (errorString) {
		[errorDescription appendString:errorString];
	}

	if (errorSource) {
		[errorDescription appendString:@" - "];
		[errorDescription appendString:errorSource];
	}

	NSError *error = [NSError errorWithDomain:kOTRKitErrorDomain
										 code:errorCode
									 userInfo:@{NSLocalizedDescriptionKey : errorDescription}];

	return error;
}

#pragma mark -
#pragma mark TLV

- (OtrlTLV *)_tlvChainForTLVs:(NSArray<OTRTLV *> *)tlvs
{
	if (tlvs == nil || [tlvs count] == 0) {
		return NULL;
	}

	OtrlTLV *root_tlv = NULL;
	OtrlTLV *current_tlv = NULL;

	NSUInteger validTLVCount = 0;

	for (OTRTLV *tlv in tlvs) {
		if ([tlv isValidLength] == NO) {
			continue;
		}

		OtrlTLV *new_tlv = otrl_tlv_new([tlv type], [[tlv data] length], [[tlv data] bytes]);

		if (validTLVCount == 0) {
			root_tlv = new_tlv;
		} else {
			current_tlv->next = new_tlv;
		}

		current_tlv = new_tlv;

		validTLVCount++;
	}

	return root_tlv;
}

- (NSArray<OTRTLV *> *)_tlvArrayForTLVChain:(OtrlTLV *)tlv_chain
{
	if (tlv_chain == NULL) {
		return nil;
	}

	NSMutableArray *tlvArray = [NSMutableArray array];

	OtrlTLV *current_tlv = tlv_chain;

	while (current_tlv) {
		NSData *tlvData = [NSData dataWithBytes:current_tlv->data length:current_tlv->len];

		OTRTLVType type = current_tlv->type;

		OTRTLV *tlv = [[OTRTLV alloc] initWithType:type data:tlvData];

		[tlvArray addObject:tlv];

		current_tlv = current_tlv->next;
	}

	return [tlvArray copy];
}

#pragma mark -
#pragma mark Context

- (ConnContext *)_contextForUsername:(NSString *)username accountName:(NSString *)accountName protocol:(NSString *)protocol
{
	ConnContext *context = otrl_context_find(self.userState, [username UTF8String], [accountName UTF8String], [protocol UTF8String], OTRL_INSTAG_BEST, NO, NULL, NULL, NULL);

	return context;
}

- (BOOL)isGeneratingKeyForAccountName:(NSString *)accountName protocol:(NSString *)protocol
{
	AssertParamaterLength(accountName)
	AssertParamaterLength(protocol)

	__block BOOL generatingKey = NO;

	[self _performSyncOperationOnInternalQueue:^{
		void *otrKey;

		gcry_error_t otrError = otrl_privkey_generate_start(self.userState, [accountName UTF8String], [protocol UTF8String], &otrKey);

		if (otrError == 0) {
			otrl_privkey_generate_cancelled(self.userState, otrKey);
		}

		generatingKey = (otrError == gcry_error(GPG_ERR_EEXIST));
	}];

	return generatingKey;
}

#pragma mark -
#pragma mark Message State Management

- (OTRKitMessageState)_messageStateForContext:(ConnContext *)otrContext
{
	if (otrContext) {
		switch (otrContext->msgstate) {
			case OTRL_MSGSTATE_ENCRYPTED:
			{
				return OTRKitMessageStateEncrypted;

				break;
			}
			case OTRL_MSGSTATE_FINISHED:
			{
				return OTRKitMessageStateFinished;

				break;
			}
			case OTRL_MSGSTATE_PLAINTEXT:
			{
				return OTRKitMessageStatePlaintext;

				break;
			}
		}
	}

	return OTRKitMessageStatePlaintext;
}

- (OTRKitMessageState)messageStateForUsername:(NSString *)username
								  accountName:(NSString *)accountName
									 protocol:(NSString *)protocol
{
	AssertParamaterLength(username)
	AssertParamaterLength(accountName)
	AssertParamaterLength(protocol)

	__block OTRKitMessageState messageState = OTRKitMessageStatePlaintext;

	[self _performSyncOperationOnInternalQueue:^{
		ConnContext *otrContext = [self _contextForUsername:username accountName:accountName protocol:protocol];

		messageState = [self _messageStateForContext:otrContext];
	}];

	return messageState;
}

- (OTRKitOfferState)_offerStateForContext:(ConnContext *)otrContext
{
	if (otrContext) {
		switch (otrContext->otr_offer) {
			case OFFER_NOT:
			{
				return OTRKitOfferStateNone;

				break;
			}
			case OFFER_ACCEPTED:
			{
				return OTRKitOfferStateAccepted;

				break;
			}
			case OFFER_REJECTED:
			{
				return OTRKitOfferStateRejected;

				break;
			}
			case OFFER_SENT:
			{
				return OTRKitOfferStateSent;

				break;
			}
		}
	}

	return OTRKitOfferStateNone;
}

- (OTRKitOfferState)offerStateForUsername:(NSString *)username
							  accountName:(NSString *)accountName
								 protocol:(NSString *)protocol
{
	AssertParamaterLength(username)
	AssertParamaterLength(accountName)
	AssertParamaterLength(protocol)

	__block OTRKitOfferState offerState = OTRKitOfferStateNone;

	[self _performSyncOperationOnInternalQueue:^{
		ConnContext *otrContext = [self _contextForUsername:username accountName:accountName protocol:protocol];

		offerState = [self _offerStateForContext:otrContext];
	}];
	
	return offerState;
}

- (OTRKitMessageType)typeOfMessage:(NSString *)message
{
	AssertParamaterLength(message)

	__block OTRKitMessageType messageType = OTRKitMessageTypeUnknown;

	[self _performSyncOperationOnInternalQueue:^{
		OtrlMessageType otrMessageType = otrl_proto_message_type([message UTF8String]);

		switch (otrMessageType) {
			case OTRL_MSGTYPE_NOTOTR:
			{
				messageType = OTRKitMessageTypeNotOTR;

				break;
			}
			case OTRL_MSGTYPE_TAGGEDPLAINTEXT:
			{
				messageType = OTRKitMessageTypeTaggedPlainText;

				break;
			}
			case OTRL_MSGTYPE_QUERY:
			{
				messageType = OTRKitMessageTypeQuery;

				break;
			}
			case OTRL_MSGTYPE_DH_COMMIT:
			{
				messageType = OTRKitMessageTypeDHCommit;

				break;
			}
			case OTRL_MSGTYPE_DH_KEY:
			{
				messageType = OTRKitMessageTypeDHKey;

				break;
			}
			case OTRL_MSGTYPE_REVEALSIG:
			{
				messageType = OTRKitMessageTypeRevealSignature;

				break;
			}
			case OTRL_MSGTYPE_SIGNATURE:
			{
				messageType = OTRKitMessageTypeSignature;

				break;
			}
			case OTRL_MSGTYPE_V1_KEYEXCH:
			{
				messageType = OTRKitMessageTypeV1KeyExchange;

				break;
			}
			case OTRL_MSGTYPE_DATA:
			{
				messageType = OTRKitMessageTypeData;

				break;
			}
			case OTRL_MSGTYPE_ERROR:
			{
				messageType = OTRKitMessageTypeError;

				break;
			}
			case OTRL_MSGTYPE_UNKNOWN:
			{
				messageType = OTRKitMessageTypeUnknown;
				
				break;
			}
		}
	}];

	return messageType;
}

#pragma mark -
#pragma mark Properties

- (OtrlPolicy)_otrlPolicy
{
	switch (self.otrPolicy) {
		case OTRKitPolicyDefault:
		{
			return OTRL_POLICY_DEFAULT;
		}
		case OTRKitPolicyAlways:
		{
			return OTRL_POLICY_ALWAYS;
		}
		case OTRKitPolicyManual:
		{
			return OTRL_POLICY_MANUAL;
		}
		case OTRKitPolicyOpportunistic:
		{
			return OTRL_POLICY_OPPORTUNISTIC;
		}
		case OTRKitPolicyNever:
		{
			return OTRL_POLICY_NEVER;
		}
		default:
		{
			return OTRL_POLICY_DEFAULT;
		}
	}
}

- (NSString *)documentsDirectory
{
	NSArray *paths = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES);

	NSString *cachedPath = [paths[0] stringByAppendingPathComponent:@"/com.codeux.frameworks.encryptionKit/OTRKit/"];

	return cachedPath;
}

- (NSString *)privateKeyPath
{
	return [self.dataPath stringByAppendingPathComponent:kOTRKitPrivateKeyFileName];
}

- (NSString *)fingerprintsPath
{
	return [self.dataPath stringByAppendingPathComponent:kOTRKitFingerprintsFileName];
}

- (NSString *)instanceTagsPath
{
	return [self.dataPath stringByAppendingPathComponent:kOTRKitInstanceTagsFileName];
}

#pragma mark
#pragma mark Fingerprint Management

- (Fingerprint *)_fingerprintForUsername:(NSString *)username accountName:(NSString *)accountName protocol:(NSString *)protocol
{
	Fingerprint *otrFingerprint = NULL;

	ConnContext *otrContext = [self _contextForUsername:username accountName:accountName protocol:protocol];

	if (otrContext) {
		otrFingerprint = otrContext->active_fingerprint;
	}

	return otrFingerprint;
}

- (NSString *)_fingerprintStringFromFingerprint:(Fingerprint *)otrFingerprint
{
	char fingerprintHash[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];

	if (otrFingerprint && otrFingerprint->fingerprint) {
		otrl_privkey_hash_to_human(fingerprintHash, otrFingerprint->fingerprint);

		return @(fingerprintHash);
	}

	return nil;
}

- (NSArray *)requestAllFingerprints
{
	__block NSArray *allFingerprints = nil;

	[self _performSyncOperationOnInternalQueue:^{
		NSMutableArray *fingerprintsArray = [NSMutableArray array];

		ConnContext *otrContext = self.userState->context_root;

		while (otrContext) {
			Fingerprint *otrFingerprint = otrContext->fingerprint_root.next;

			while (otrFingerprint) {
				/* Gather information about the current fingerprint. */
				NSString *fingerprintString = [self _fingerprintStringFromFingerprint:otrFingerprint];

				NSString *username = @(otrContext->username);
				NSString *accountName = @(otrContext->accountname);

				NSString *protocol = @(otrContext->protocol);

				BOOL isTrusted = (otrl_context_is_fingerprint_trusted(otrFingerprint) == true);

				/* Build a concrete object around the information gathered */
				OTRKitConcreteObject *resultObject = [OTRKitConcreteObject new];

				[resultObject setUsername:username];
				[resultObject setAccountName:accountName];

				[resultObject setProtocol:protocol];

				[resultObject setFingerprint:otrFingerprint];
				[resultObject setFingerprintString:fingerprintString];

				[resultObject setFingerprintIsTrusted:isTrusted];

				[fingerprintsArray addObject:resultObject];

				/* Move on to the next fingerprint in the chain */
				otrFingerprint = otrFingerprint->next;
			}

			otrContext = otrContext->next;
		}

		allFingerprints = [fingerprintsArray copy];
	}];

	return allFingerprints;
}

- (void)deleteFingerprint:(NSString *)fingerprint
				 username:(NSString *)username
			  accountName:(NSString *)accountName
				 protocol:(NSString *)protocol
{
	AssertParamaterLength(fingerprint)
	AssertParamaterLength(username)
	AssertParamaterLength(accountName)
	AssertParamaterLength(protocol)

	[self _performAsyncOperationOnInternalQueue:^{
		ConnContext *otrContext = [self _contextForUsername:username accountName:accountName protocol:protocol];

		if (otrContext == NULL) {
			return;
		}

		Fingerprint *otrFingerprint = NULL;

		Fingerprint *otrFingerprintCurrent = otrContext->fingerprint_root.next;

		while (otrFingerprintCurrent) {
			char fingerprintHash[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];

			otrl_privkey_hash_to_human(fingerprintHash, otrFingerprintCurrent->fingerprint);

			NSString *fingerprintCurrent = @(fingerprintHash);

			if ([fingerprintCurrent isEqualToString:fingerprint]) {
				otrFingerprint = otrFingerprintCurrent;

				break;
			} else {
				otrFingerprintCurrent = otrFingerprintCurrent->next;
			}
		}

		if (otrFingerprint) {
			[self _deleteFingerprint:otrFingerprint username:username accountName:accountName protocol:protocol];
		}
	}];
}

- (void)deleteFingerprintWithConcreteObject:(OTRKitConcreteObject *)fingerprint
{
	AssertParamaterNil(fingerprint)

	[self _performAsyncOperationOnInternalQueue:^{
		[self _deleteFingerprint:[fingerprint fingerprint] username:[fingerprint username] accountName:[fingerprint accountName] protocol:[fingerprint protocol]];
	}];
}

- (void)_deleteFingerprint:(Fingerprint *)otrFingerprint username:(NSString *)username accountName:(NSString *)accountName protocol:(NSString *)protocol
{
	AssertParamaterNull(otrFingerprint)

	AssertParamaterLength(username)
	AssertParamaterLength(accountName)
	AssertParamaterLength(protocol)

	Fingerprint *otrFingerprintActive = [self _fingerprintForUsername:username accountName:accountName protocol:protocol];

	if (otrFingerprint == otrFingerprintActive) {
		; // Cannot delete the active fingerprint...
	} else {
		[self _deleteFingerprint:otrFingerprint];
	}
}

- (void)_deleteFingerprint:(Fingerprint *)otrFingerprint
{
	if (otrFingerprint) {
		otrl_context_forget_fingerprint(otrFingerprint, 0);

		[self _writeFingerprintsPath];
	}
}

- (NSString *)fingerprintForAccountName:(NSString *)accountName
							   protocol:(NSString *)protocol
{
	AssertParamaterLength(accountName)
	AssertParamaterLength(protocol)

	__block NSString *fingerprintString = nil;

	[self _performSyncOperationOnInternalQueue:^{
		char fingerprintHash[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];

		otrl_privkey_fingerprint(self.userState, fingerprintHash, [accountName UTF8String], [protocol UTF8String]);

		fingerprintString = @(fingerprintHash);
	}];

	return fingerprintString;
}

- (NSString *)activeFingerprintForUsername:(NSString *)username
							   accountName:(NSString *)accountName
								  protocol:(NSString *)protocol
{
	AssertParamaterLength(username)
	AssertParamaterLength(accountName)
	AssertParamaterLength(protocol)

	__block NSString *fingerprintString = nil;

	[self _performSyncOperationOnInternalQueue:^{
		Fingerprint *otrFingerprint = [self _fingerprintForUsername:username accountName:accountName protocol:protocol];

		if (otrFingerprint) {
			fingerprintString = [self _fingerprintStringFromFingerprint:otrFingerprint];
		}
	}];

	return fingerprintString;
}

- (BOOL)activeFingerprintIsVerifiedForUsername:(NSString *)username
								   accountName:(NSString *)accountName
									  protocol:(NSString *)protocol
{
	AssertParamaterLength(username)
	AssertParamaterLength(accountName)
	AssertParamaterLength(protocol)

	__block BOOL verified = NO;

	[self _performSyncOperationOnInternalQueue:^{
		Fingerprint *otrFingerprint = [self _fingerprintForUsername:username accountName:accountName protocol:protocol];

		if (otrFingerprint && otrFingerprint->trust) {
			if (otrl_context_is_fingerprint_trusted(otrFingerprint) == true) {
				verified = YES;
			}
		}
	}];

	return verified;
}

- (void)setActiveFingerprintVerificationForUsername:(NSString *)username
										accountName:(NSString *)accountName
										   protocol:(NSString *)protocol
										   verified:(BOOL)verified
{
	AssertParamaterLength(username)
	AssertParamaterLength(accountName)
	AssertParamaterLength(protocol)

	[self _performAsyncOperationOnInternalQueue:^{
		Fingerprint *otrFingerprint = [self _fingerprintForUsername:username accountName:accountName protocol:protocol];

		if (otrFingerprint) {
			[self _setVerificationForFingerprint:otrFingerprint verified:verified];

			[self _postDelegateVerifiedStateChangedForUsername:username accountName:accountName protocol:protocol verified:verified];
		}
	}];
}

- (void)setFingerprintVerificationForConcreteObject:(OTRKitConcreteObject *)fingerprint verified:(BOOL)verified
{
	AssertParamaterNil(fingerprint)

	[self _performAsyncOperationOnInternalQueue:^{
		Fingerprint *otrFingerprint = [fingerprint fingerprint];

		if (otrFingerprint) {
			/* Set the fingerprint on our reference fingerprint */
			[self _setVerificationForFingerprint:otrFingerprint verified:verified];

			/* Compare our reference fingerprint against that of the user */
			Fingerprint *otrFingerprintActive = [self _fingerprintForUsername:[fingerprint username] accountName:[fingerprint accountName] protocol:[fingerprint protocol]];

			if (otrFingerprint == otrFingerprintActive) {
				[self _postDelegateVerifiedStateChangedForUsername:[fingerprint username] accountName:[fingerprint accountName] protocol:[fingerprint protocol] verified:verified];
			}
		}
	}];
}

- (void)_setVerificationForFingerprint:(Fingerprint *)otrFingerprint verified:(BOOL)verified
{
	const char *newTrust = NULL;

	if (verified) {
		newTrust = "verified";
	}

	otrl_context_set_trust(otrFingerprint, newTrust);

	[self _writeFingerprintsPath];
}

#pragma mark -
#pragma mark Read Data and Write Data

- (void)_readPrivateKeyPath
{
	NSString *path = self.privateKeyPath;

	FILE *filePointer = fopen([path UTF8String], "rb");

	if (filePointer) {
		otrl_privkey_read_FILEp(self.userState, filePointer);
	}

	fclose(filePointer);
}

- (void)_readFingerprintsPath
{
	NSString *path = self.fingerprintsPath;

	FILE *filePointer = fopen([path UTF8String], "rb");

	if (filePointer) {
		otrl_privkey_read_fingerprints_FILEp(self.userState, filePointer, NULL, NULL);
	}

	fclose(filePointer);
}

- (void)_readInstanceTagsPath
{
	NSString *path = self.instanceTagsPath;

	FILE *filePointer = fopen([path UTF8String], "rb");

	if (filePointer) {
		otrl_instag_read_FILEp(self.userState, filePointer);
	}

	fclose(filePointer);
}

- (void)_writeFingerprintsPath
{
	NSString *path = self.fingerprintsPath;

	FILE *filePointer = fopen([path UTF8String], "wb");

	if (filePointer == NULL) {
		return;
	}

	otrl_privkey_write_fingerprints_FILEp(self.userState, filePointer);

	fclose(filePointer);

	[self _postFingerprintsDidChangeNotification];
}

#pragma mark -
#pragma mark Delegate Callbacks and Notifications

- (void)_postDelegateVerifiedStateChangedForUsername:(NSString *)username accountName:(NSString *)accountName protocol:(NSString *)protocol verified:(BOOL)verified
{
	[self _performAsyncOperationOnDelegateQueue:^{
		[self.delegate otrKit:self fingerprintIsVerifiedStateChangedForUsername:username accountName:accountName protocol:protocol verified:verified];
	}];
}

- (void)_postFingerprintsDidChangeNotification
{
	[self _performAsyncOperationOnDelegateQueue:^{
		[[NSNotificationCenter defaultCenter] postNotificationName:OTRKitListOfFingerprintsDidChangeNotification object:self];
	}];
}

- (void)_postMessageStateDidChangeNotification
{
	[self _performAsyncOperationOnDelegateQueue:^{
		[[NSNotificationCenter defaultCenter] postNotificationName:OTRKitMessageStateDidChangeNotification object:self];
	}];
}

- (void)_updateEncryptionStatusWithContext:(ConnContext *)context
{
	NSString *username = @(context->username);
	NSString *accountName = @(context->accountname);

	NSString *protocol = @(context->protocol);

	OTRKitMessageState messageState = [self messageStateForUsername:username accountName:accountName protocol:protocol];

	[self _performAsyncOperationOnDelegateQueue:^{
		[self.delegate otrKit:self updateMessageState:messageState username:username accountName:accountName protocol:protocol];
	}];

	[self _postMessageStateDidChangeNotification];
}

#pragma mark
#pragma mark Symmetric Key

- (void)requestSymmetricKeyForUsername:(NSString *)username
						   accountName:(NSString *)accountName
							  protocol:(NSString *)protocol
								forUse:(NSUInteger)use
							   useData:(NSData *)useData
							completion:(void (^)(NSData *key, NSError *error))completion
{
	AssertParamaterLength(username)
	AssertParamaterLength(accountName)
	AssertParamaterLength(protocol)
	AssertParamaterLength(useData)

	[self _performAsyncOperationOnInternalQueue:^{
		ConnContext *otrContext = [self _contextForUsername:username accountName:accountName protocol:protocol];

		if (otrContext == NULL) {
			return;
		}

		uint8_t *symmetricKeyBytes = malloc(OTRL_EXTRAKEY_BYTES * sizeof(uint8_t));

		gcry_error_t otrError = otrl_message_symkey(self.userState, &ui_ops, NULL, otrContext, (unsigned int)use, [useData bytes], [useData length], symmetricKeyBytes);

		NSData *symmetricKey = nil;

		NSError *errorString = nil;

		if (otrError == gcry_err_code(GPG_ERR_NO_ERROR)) {
			symmetricKey = [[NSData alloc] initWithBytes:symmetricKeyBytes length:OTRL_EXTRAKEY_BYTES];
		} else {
			errorString = [self _errorForGPGError:otrError];
		}

		[self _performAsyncOperationOnDelegateQueue:^{
			if (completion) {
				completion(symmetricKey, errorString);
			}
		}];
	}];
}

#pragma mark
#pragma mark Socialist Millionaire Problem

- (void) initiateSMPForUsername:(NSString *)username
					accountName:(NSString *)accountName
					   protocol:(NSString *)protocol
						 secret:(NSString *)secret
{
	AssertParamaterLength(username)
	AssertParamaterLength(accountName)
	AssertParamaterLength(protocol)
	AssertParamaterLength(secret)

	[self _performAsyncOperationOnInternalQueue:^{
		ConnContext *otrContext = [self _contextForUsername:username accountName:accountName protocol:protocol];

		if (otrContext == NULL) {
			return;
		}

		NSData *secretBytes = [secret dataUsingEncoding:NSUTF8StringEncoding];

		otrl_message_initiate_smp(self.userState, &ui_ops, NULL, otrContext, [secretBytes bytes], [secretBytes length]);
	}];
}

- (void) initiateSMPForUsername:(NSString *)username
					accountName:(NSString *)accountName
					   protocol:(NSString *)protocol
					   question:(NSString *)question
						 secret:(NSString *)secret
{
	AssertParamaterLength(username)
	AssertParamaterLength(accountName)
	AssertParamaterLength(protocol)
	AssertParamaterLength(question)
	AssertParamaterLength(secret)

	[self _performAsyncOperationOnInternalQueue:^{
		ConnContext *otrContext = [self _contextForUsername:username accountName:accountName protocol:protocol];

		if (otrContext == NULL) {
			return;
		}

		NSData *secretBytes = [secret dataUsingEncoding:NSUTF8StringEncoding];

		otrl_message_initiate_smp_q(self.userState, &ui_ops, NULL, otrContext, [question UTF8String], [secretBytes bytes], [secretBytes length]);
	}];
}

- (void)respondToSMPForUsername:(NSString *)username
					accountName:(NSString *)accountName
					   protocol:(NSString *)protocol
						 secret:(NSString *)secret
{
	AssertParamaterLength(username)
	AssertParamaterLength(accountName)
	AssertParamaterLength(protocol)
	AssertParamaterLength(secret)

	[self _performAsyncOperationOnInternalQueue:^{
		ConnContext *otrContext = [self _contextForUsername:username accountName:accountName protocol:protocol];

		if (otrContext == NULL) {
			return;
		}

		NSData *secretBytes = [secret dataUsingEncoding:NSUTF8StringEncoding];

		otrl_message_respond_smp(self.userState, &ui_ops, NULL, otrContext, [secretBytes bytes], [secretBytes length]);
	}];
}

- (void)abortSMPForUsername:(NSString *)username
				accountName:(NSString *)accountName
				   protocol:(NSString *)protocol
{
	AssertParamaterLength(username)
	AssertParamaterLength(accountName)
	AssertParamaterLength(protocol)

	[self _performAsyncOperationOnInternalQueue:^{
		ConnContext *otrContext = [self _contextForUsername:username accountName:accountName protocol:protocol];

		if (otrContext == NULL) {
			return;
		}

		otrl_message_abort_smp(self.userState, &ui_ops, NULL, otrContext);
	}];
}

#pragma mark -
#pragma mark Grand Central Dispatch

- (void)_performAsyncOperationOnDelegateQueue:(dispatch_block_t)block
{
	[self _performBlockOnDelegateQueue:block asynchronously:YES];
}

- (void)_performSyncOperationOnDelegateQueue:(dispatch_block_t)block
{
	[self _performBlockOnDelegateQueue:block asynchronously:NO];
}

- (void)_performBlockOnDelegateQueue:(dispatch_block_t)block asynchronously:(BOOL)asynchronously
{
	if (self.delegate == nil) {
		return;
	}

	dispatch_queue_t delegateQueue = self.delegateQueue;

	if (delegateQueue == NULL) {
		/* The main queue is defaulted to if the delegate does not specify one.
		 Check if this is the main thread (or queue) and may just invoke block. */
		if ([NSThread isMainThread]) {
			block();

			return;
		}

		delegateQueue = dispatch_get_main_queue();
	}

	if (asynchronously) {
		dispatch_async(delegateQueue, block);
	} else {
		dispatch_sync(delegateQueue, block);
	}
}

- (void)_performAsyncOperationOnInternalQueue:(dispatch_block_t)block
{
	[self _performBlockOnInternalQueue:block asynchronously:YES];
}

- (void)_performSyncOperationOnInternalQueue:(dispatch_block_t)block
{
	[self _performBlockOnInternalQueue:block asynchronously:NO];
}

- (void)_performBlockOnInternalQueue:(dispatch_block_t)block asynchronously:(BOOL)asynchronously
{
	if (dispatch_get_specific(IsOnInternalQueueKey)) {
		block();

		return;
	}

	if (asynchronously) {
		dispatch_async(self.internalQueue, block);
	} else {
		dispatch_sync(self.internalQueue, block);
	}
}

#pragma mark -
#pragma Account Name Separator

- (NSString *)rightPortionOfAccountName:(NSString *)accountName
{
	AssertParamaterLength(accountName)

	NSString *accountNameSeparator = self.accountNameSeparator;

	NSRange sequenceRange = [accountName rangeOfString:accountNameSeparator options:NSBackwardsSearch];

	if (sequenceRange.location == NSNotFound) {
		return nil;
	}

	NSInteger sliceRange = (sequenceRange.location + [accountNameSeparator length]);

	if (sliceRange >= [accountName length]) {
		return nil;
	}

	NSString *username = [accountName substringFromIndex:sliceRange];

	return username;
}

- (NSString *)leftPortionOfAccountName:(NSString *)accountName
{
	AssertParamaterLength(accountName)

	NSString *accountNameSeparator = self.accountNameSeparator;

	NSRange sequenceRange = [accountName rangeOfString:accountNameSeparator options:NSBackwardsSearch];

	NSInteger sliceRange = sequenceRange.location;

	if (sliceRange == NSNotFound) {
		return nil;
	}
	
	NSString *username = [accountName substringToIndex:sliceRange];
	
	return username;
}

#pragma mark -
#pragma mark Static Methods

+ (BOOL)stringStartsWithOTRPrefix:(NSString *)string
{
	return [string hasPrefix:@"?OTR"];
}

+ (NSString *)libotrVersion
{
	return @(otrl_version());
}

+ (NSString *)libgcryptVersion
{
	return @(gcry_check_version(NULL));
}

+ (NSString *)libgpgErrorVersion
{
	return @(gpg_error_check_version(NULL));
}

@end
