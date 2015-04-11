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

NSString * const OTRKitPrepareForApplicationTerminationNotification = @"OTRKitPrepareForApplicationTerminationNotification";

@implementation OTRKit

#pragma mark libotr ui_ops callback functions

static OtrlPolicy policy_cb(void *opdata, ConnContext *context)
{
	OTRKit *otrKit = [OTRKit sharedInstance];

	return [otrKit otrlPolicy];
}

static void create_privkey_cb(void *opdata, const char *accountname, const char *protocol)
{
	OTRKit *otrKit = [OTRKit sharedInstance];

	NSString *accountNameString = @(accountname);
	NSString *protocolString = @(protocol);

	if ([otrKit delegate]) {
		[otrKit performAsyncOperationOnMainQueue:^{
			[[otrKit delegate] otrKit:otrKit willStartGeneratingPrivateKeyForAccountName:accountNameString protocol:protocolString];
		}];
	}

	void *newkeyp;

	gcry_error_t generateError = otrl_privkey_generate_start([otrKit userState], accountname, protocol, &newkeyp);

	NSString *path = [otrKit privateKeyPath];

	FILE *privf = fopen([path UTF8String], "w+b");

	if (generateError == gcry_error(GPG_ERR_NO_ERROR)) {
		otrl_privkey_generate_calculate(newkeyp);
		otrl_privkey_generate_finish_FILEp([otrKit userState], newkeyp, privf);

		if ([otrKit delegate]) {
			[otrKit performAsyncOperationOnMainQueue:^{
				[[otrKit delegate] otrKit:otrKit didFinishGeneratingPrivateKeyForAccountName:accountNameString protocol:protocolString error:nil];
			}];
		}
	} else {
		NSError *error = [otrKit errorForGPGError:generateError];

		if ([otrKit delegate]) {
			[otrKit performAsyncOperationOnMainQueue:^{
				[[otrKit delegate] otrKit:otrKit didFinishGeneratingPrivateKeyForAccountName:accountNameString protocol:protocolString error:error];
			}];
		}
	}

	fclose(privf);
}

static int is_logged_in_cb(void *opdata, const char *accountname, const char *protocol, const char *recipient)
{
	OTRKit *otrKit = [OTRKit sharedInstance];

	if ([otrKit delegate] == nil) {
		return (-1);
	}

	__block BOOL loggedIn = NO;

	[otrKit performAsyncOperationOnMainQueue:^{
		loggedIn = [[otrKit delegate] otrKit:otrKit
						  isUsernameLoggedIn:@(recipient)
								 accountName:@(accountname)
									protocol:@(protocol)];
	}];

	return loggedIn;
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

	[otrKit performAsyncOperationOnMainQueue:^{
		[[otrKit delegate] otrKit:otrKit injectMessage:messageString username:usernameString accountName:accountNameString protocol:protocolString tag:tag];
	}];
}

static void update_context_list_cb(void *opdata)
{
}

static void confirm_fingerprint_cb(void *opdata, OtrlUserState us, const char *accountname, const char *protocol, const char *username, unsigned char fingerprint[20])
{
	OTRKit *otrKit = [OTRKit sharedInstance];

	char our_hash[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
	char their_hash[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];

	ConnContext *context = otrl_context_find([otrKit userState], username, accountname, protocol, OTRL_INSTAG_BEST, NO, NULL, NULL, NULL);

	if (context == NULL) {
		return;
	}

	otrl_privkey_fingerprint([otrKit userState], our_hash, context->accountname, context->protocol);

	otrl_privkey_hash_to_human(their_hash, fingerprint);

	NSString *ourHash = @(our_hash);
	NSString *theirHash = @(their_hash);

	NSString *accountNameString = @(accountname);
	NSString *usernameString = @(username);

	NSString *protocolString = @(protocol);

	[otrKit performAsyncOperationOnMainQueue:^{
		[[otrKit delegate] otrKit:otrKit showFingerprintConfirmationForTheirHash:theirHash ourHash:ourHash username:usernameString accountName:accountNameString protocol:protocolString];
	}];
}

static void write_fingerprints_cb(void *opdata)
{
	OTRKit *otrKit = [OTRKit sharedInstance];

	NSString *path = [otrKit fingerprintsPath];

	FILE *storef = fopen([path UTF8String], "wb");

	if (storef == NULL) {
		return;
	}

	otrl_privkey_write_fingerprints_FILEp([otrKit userState], storef);

	fclose(storef);

	[otrKit postFingerprintsDidChangeNotification];
}

static void gone_secure_cb(void *opdata, ConnContext *context)
{
	OTRKit *otrKit = [OTRKit sharedInstance];

	[otrKit updateEncryptionStatusWithContext:context];
}

/**
 *  This method is never called due to a bug in libotr 4.0.0
 */
static void gone_insecure_cb(void *opdata, ConnContext *context)
{
	OTRKit *otrKit = [OTRKit sharedInstance];

	[otrKit updateEncryptionStatusWithContext:context];
}

static void still_secure_cb(void *opdata, ConnContext *context, int is_reply)
{
	OTRKit *otrKit = [OTRKit sharedInstance];

	[otrKit updateEncryptionStatusWithContext:context];
}

static int max_message_size_cb(void *opdata, ConnContext *context)
{
	NSString *protocol = @(context->protocol);

	if ([protocol length] <= 0) {
		return 0;
	}

	OTRKit *otrKit = [OTRKit sharedInstance];

	NSNumber *maxMessageSize = [otrKit protocolMaxSize][protocol];

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

static const char *resent_msg_prefix_cb(void *opdata, ConnContext *context)
{
	NSString *resentString = @"[resent]";

	return [resentString UTF8String];
}

static void resent_msg_prefix_free_cb(void *opdata, const char *prefix)
{
	// Leak memory here instead of crashing:
	// if (prefix) free((char*)prefix);
}

static void handle_smp_event_cb(void *opdata, OtrlSMPEvent smp_event, ConnContext *context, unsigned short progress_percent, char *question)
{
	OTRKit *otrKit = [OTRKit sharedInstance];

	OTRKitSMPEvent event = OTRKitSMPEventNone;

	if (context == NULL) {
		return;
	}

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

			otrl_message_abort_smp([otrKit userState], &ui_ops, opdata, context);

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

			otrl_message_abort_smp([otrKit userState], &ui_ops, opdata, context);

			break;
		}
	}

	NSString *questionString = nil;

	if (question) {
		questionString = @(question);
	}

	NSString *username = @(context->username);
	NSString *accountName = @(context->accountname);

	NSString *protocol = @(context->protocol);

	[otrKit performAsyncOperationOnMainQueue:^{
		[[otrKit delegate] otrKit:otrKit handleSMPEvent:event progress:progress_percent question:questionString username:username accountName:accountName protocol:protocol];
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

	NSError *error = [otrKit errorForGPGError:err];

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

	NSString *username = @(context->username);
	NSString *accountName = @(context->accountname);

	NSString *protocol = @(context->protocol);

	id tag = (__bridge id)(opdata);

	[otrKit performAsyncOperationOnMainQueue:^{
		[[otrKit delegate] otrKit:otrKit handleMessageEvent:event message:messageString username:username accountName:accountName protocol:protocol tag:tag error:error];
	}];
}

static void create_instag_cb(void *opdata, const char *accountname, const char *protocol)
{
	OTRKit *otrKit = [OTRKit sharedInstance];

	NSString *path = [otrKit instanceTagsPath];

	FILE *instagf = fopen([path UTF8String], "w+b");

	otrl_instag_generate_FILEp([otrKit userState], instagf, accountname, protocol);

	fclose(instagf);
}

static void timer_control_cb(void *opdata, unsigned int interval)
{
	OTRKit *otrKit = [OTRKit sharedInstance];

	[otrKit performAsyncOperationOnMainQueue:^{
		if ( [otrKit pollTimer]) {
			[[otrKit pollTimer] invalidate];

			[otrKit setPollTimer:nil];
		}

		if (interval > 0) {
			[otrKit setPollTimer:[NSTimer scheduledTimerWithTimeInterval:interval target:otrKit selector:@selector(messagePoll:) userInfo:nil repeats:YES]];
		}
	}];
}

static void received_symkey_cb(void *opdata, ConnContext *context, unsigned int use, const unsigned char *usedata, size_t usedatalen, const unsigned char *symkey)
{
	OTRKit *otrKit = [OTRKit sharedInstance];

	NSData *symmetricKey = [[NSData alloc] initWithBytes:symkey length:OTRL_EXTRAKEY_BYTES];

	NSData *useDescriptionData = [[NSData alloc] initWithBytes:usedata length:usedatalen];

	NSString *username = @(context->username);
	NSString *accountName = @(context->accountname);

	NSString *protocol = @(context->protocol);

	[otrKit performAsyncOperationOnMainQueue:^{
		[[otrKit delegate] otrKit:otrKit receivedSymmetricKey:symmetricKey forUse:use useData:useDescriptionData username:username accountName:accountName protocol:protocol];
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
	resent_msg_prefix_cb,
	resent_msg_prefix_free_cb,
	handle_smp_event_cb,
	handle_msg_event_cb,
	create_instag_cb,
	NULL,		    /* convert_data */
	NULL,		    /* convert_data_free */
	timer_control_cb
};

#pragma mark Initialization

+ (instancetype)sharedInstance
{
	static OTRKit *_sharedInstance = nil;

	static dispatch_once_t onceToken;

	dispatch_once(&onceToken, ^{
		_sharedInstance = [[OTRKit alloc] init];
	});

	return _sharedInstance;
}

- (void)dealloc
{
	if ( self.pollTimer) {
		[self.pollTimer invalidate];
	}

	otrl_userstate_free(self.userState);

	self.userState = NULL;
}

- (instancetype)init
{
	if ((self = [super init])) {
		[self performSyncOperationOnMainQueue:^{
			OTRL_INIT;

			self.accountNameSeparator = @"@";

			NSDictionary *protocolDefaults = @{@"prpl-msn":   @(1409),
											   @"prpl-icq":   @(2346),
											   @"prpl-aim":   @(2343),
											   @"prpl-yahoo": @(832),
											   @"prpl-gg":    @(1999),
											   @"prpl-irc":   @(400),
											   @"prpl-oscar": @(2343)};

			self.protocolMaxSize = [NSMutableDictionary dictionaryWithDictionary:protocolDefaults];

			self.userState = otrl_userstate_create();
		}];
	}

	return self;
}

- (void)setupWithDataPath:(NSString *)dataPath
{
	if (dataPath == nil) {
		self.dataPath = [self documentsDirectory];
	} else {
		self.dataPath = dataPath;
	}

	[self readLibotrConfiguration];
}

- (void)readLibotrConfiguration
{
	[self performAsyncOperationOnMainQueue:^{
		NSString *path1 = [self privateKeyPath];

		FILE *privf = fopen([path1 UTF8String], "rb");

		if (privf) {
			otrl_privkey_read_FILEp(_userState, privf);
		}

		fclose(privf);

		// ------ //

		NSString *path2 = [self fingerprintsPath];

		FILE *storef = fopen([path2 UTF8String], "rb");

		if (storef) {
			otrl_privkey_read_fingerprints_FILEp(_userState, storef, NULL, NULL);
		}

		fclose(storef);

		// ------ //

		NSString *path3 = [self instanceTagsPath];

		FILE *tagf = fopen([path3 UTF8String], "rb");

		if (tagf) {
			otrl_instag_read_FILEp(_userState, tagf);
		}

		fclose(tagf);
	}];
}

- (NSString *)documentsDirectory
{
	NSArray *paths = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES);

	NSString *cachedPath = [paths[0] stringByAppendingPathComponent:@"/com.codeux.frameworks.encryptionKit/OTRKit/"];

	return cachedPath;
}

- (NSString *)privateKeyPath
{
	return [[self dataPath] stringByAppendingPathComponent:kOTRKitPrivateKeyFileName];
}

- (NSString *)fingerprintsPath
{
	return [[self dataPath] stringByAppendingPathComponent:kOTRKitFingerprintsFileName];
}

- (NSString *)instanceTagsPath
{
	return [[self dataPath] stringByAppendingPathComponent:kOTRKitInstanceTagsFileName];
}

- (void)setMaximumProtocolSize:(int)maxSize forProtocol:(NSString *)protocol
{
	CheckParamaterForNilValue(protocol)

	[self performAsyncOperationOnMainQueue:^{
		[self protocolMaxSize][protocol] = @(maxSize);
	}];
}

- (void)messagePoll:(NSTimer *)timer
{
	[self performAsyncOperationOnMainQueue:^{
		if ([self userState]) {
			otrl_message_poll(_userState, &ui_ops, NULL);
		} else {
			[timer invalidate];
		}
	}];
}

#pragma mark Initialization

- (void)decodeMessage:(NSString *)message
			 username:(NSString *)sender
		  accountName:(NSString *)accountName
			 protocol:(NSString *)protocol
				  tag:(id)tag
{
	CheckParamaterForNilValue(message)

	CheckParamaterForNilValue(sender)
	CheckParamaterForNilValue(accountName)
	CheckParamaterForNilValue(protocol)

	[self performAsyncOperationOnMainQueue:^{
		if ([message length] <= 0 || [sender length] <= 0 || [accountName length] <= 0 || [protocol length] <= 0) {
			return;
		}

		char *newMessage = NULL;

		ConnContext *context = [self contextForUsername:sender accountName:accountName protocol:protocol];

		OtrlTLV *otr_tlvs = NULL;

		int ignore_message = otrl_message_receiving(_userState, &ui_ops, (__bridge void *)tag, [accountName UTF8String], [protocol UTF8String], [sender UTF8String], [message UTF8String], &newMessage, &otr_tlvs, &context, NULL, NULL);

		NSString *decodedMessage = nil;

		NSArray *tlvs = nil;

		if (otr_tlvs) {
			tlvs = [self tlvArrayForTLVChain:otr_tlvs];
		}

		if (context) {
			if (context->msgstate == OTRL_MSGSTATE_FINISHED) {
				[self disableEncryptionWithUsername:sender accountName:accountName protocol:protocol];
			}
		}

		BOOL wasEncrypted = [OTRKit stringStartsWithOTRPrefix:message];

		if (ignore_message == 0)
		{
			if (newMessage) {
				decodedMessage = @(newMessage);
			} else {
				decodedMessage = message; // Nothing changed...
			}

			if ([self delegate]) {
				[[self delegate] otrKit:self
						 decodedMessage:decodedMessage
						   wasEncrypted:wasEncrypted
								   tlvs:tlvs
							   username:sender
							accountName:accountName
							   protocol:protocol
									tag:tag];
			}
		} else if (tlvs) {
			if ([self delegate]) {
				[[self delegate] otrKit:self
						 decodedMessage:nil
						   wasEncrypted:wasEncrypted
								   tlvs:tlvs
							   username:sender
							accountName:accountName
							   protocol:protocol
									tag:tag];
			}
		}

		if (newMessage) {
			otrl_message_free(newMessage);
		}

		if (otr_tlvs) {
			otrl_tlv_free(otr_tlvs);
		}
	}];
}

- (void)encodeMessage:(NSString *)messageToBeEncoded
				 tlvs:(NSArray *)tlvs
			 username:(NSString *)username
		  accountName:(NSString *)accountName
			 protocol:(NSString *)protocol
				  tag:(id)tag
{
	CheckParamaterForNilValue(messageToBeEncoded)

	CheckParamaterForNilValue(username)
	CheckParamaterForNilValue(accountName)
	CheckParamaterForNilValue(protocol)

	[self performAsyncOperationOnMainQueue:^{
		gcry_error_t err;

		char *newMessage = NULL;

		ConnContext *context = [self contextForUsername:username accountName:accountName protocol:protocol];

		// Set nil messages to empty string if TLVs are present, otherwise libotr
		// will silence the message, even though you may have meant to inject a TLV.

		NSString *message = messageToBeEncoded;

		if (messageToBeEncoded == nil && [tlvs count]) {
			message = @"";
		}

		OtrlTLV *otr_tlvs = [self tlvChainForTLVs:tlvs];

		err = otrl_message_sending(_userState, &ui_ops, (__bridge void *)(tag),
								   [accountName UTF8String], [protocol UTF8String], [username UTF8String], OTRL_INSTAG_BEST, [message UTF8String], otr_tlvs, &newMessage, OTRL_FRAGMENT_SEND_ALL, &context,
								   NULL, NULL);

		if (otr_tlvs) {
			otrl_tlv_free(otr_tlvs);
		}

		BOOL wasEncrypted = NO;

		NSString *encodedMessage = nil;

		if (newMessage) {
			encodedMessage = @(newMessage);

			otrl_message_free(newMessage);

			wasEncrypted = [OTRKit stringStartsWithOTRPrefix:encodedMessage];
		}

		NSError *error = nil;

		if ((err == 0) == NO) {
			error = [self errorForGPGError:err];

			encodedMessage = nil;
		}

		if ([self delegate]) {
			[[self delegate] otrKit:self
					 encodedMessage:encodedMessage
					   wasEncrypted:wasEncrypted
						   username:username
						accountName:accountName
						   protocol:protocol
								tag:tag
							  error:error];
		}
	}];
}

- (void)initiateEncryptionWithUsername:(NSString *)recipient
						   accountName:(NSString *)accountName
							  protocol:(NSString *)protocol
{
	CheckParamaterForNilValue(recipient)
	CheckParamaterForNilValue(accountName)
	CheckParamaterForNilValue(protocol)

	[self encodeMessage:@"?OTR?" tlvs:nil username:recipient accountName:accountName protocol:protocol tag:nil];
}

- (void)disableEncryptionWithUsername:(NSString *)recipient
						  accountName:(NSString *)accountName
							 protocol:(NSString *)protocol
{
	CheckParamaterForNilValue(recipient)
	CheckParamaterForNilValue(accountName)
	CheckParamaterForNilValue(protocol)

	[self performAsyncOperationOnMainQueue:^{
		otrl_message_disconnect_all_instances(_userState, &ui_ops, NULL, [accountName UTF8String], [protocol UTF8String], [recipient UTF8String]);

		ConnContext *context = [self contextForUsername:recipient accountName:accountName protocol:protocol];

		if (context) {
			[self updateEncryptionStatusWithContext:context];
		}
	}];
}

- (BOOL)isGeneratingKeyForAccountName:(NSString *)accountName protocol:(NSString *)protocol
{
	CheckParamaterForNilValueR(accountName, NO)
	CheckParamaterForNilValueR(protocol, NO)

	__block BOOL generatingKey = NO;

	[self performSyncOperationOnMainQueue:^{
		void *newkeyp;

		gcry_error_t generateError = otrl_privkey_generate_start(_userState, [accountName UTF8String], [protocol UTF8String], &newkeyp);

		if ((generateError == 0) == NO) {
			otrl_privkey_generate_cancelled(_userState, newkeyp);
		}

		generatingKey = (generateError == gcry_error(GPG_ERR_EEXIST));
	}];

	return generatingKey;
}

- (void)updateEncryptionStatusWithContext:(ConnContext *)context
{
	if ([self delegate]) {
		NSString *username = @(context->username);
		NSString *accountName = @(context->accountname);

		NSString *protocol = @(context->protocol);

		OTRKitMessageState messageState = [self messageStateForUsername:username accountName:accountName protocol:protocol];

		[self performAsyncOperationOnMainQueue:^{
			[[self delegate] otrKit:self updateMessageState:messageState username:username accountName:accountName protocol:protocol];
		}];

		[self postMessageStateDidChangeNotification];
	}
}

- (NSError *)errorForGPGError:(gcry_error_t)gpg_error
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
		[errorDescription appendString:errorSource];
	}

	NSError *error = [NSError errorWithDomain:kOTRKitErrorDomain code:errorCode userInfo:@{NSLocalizedDescriptionKey:errorDescription}];

	return error;
}

- (OtrlTLV *)tlvChainForTLVs:(NSArray *)tlvs
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

- (NSArray *)tlvArrayForTLVChain:(OtrlTLV *)tlv_chain
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

	return tlvArray;
}

- (ConnContext *)contextForUsername:(NSString *)username accountName:(NSString *)accountName protocol:(NSString *)protocol
{
	ConnContext *context = otrl_context_find(_userState, [username UTF8String], [accountName UTF8String], [protocol UTF8String], OTRL_INSTAG_BEST, NO, NULL, NULL, NULL);

	return context;
}

- (Fingerprint *)internalActiveFingerprintForUsername:(NSString *)username accountName:(NSString *)accountName protocol:(NSString *)protocol
{
	Fingerprint *fingerprint = NULL;

	ConnContext *context = [self contextForUsername:username accountName:accountName protocol:protocol];

	if (context) {
		fingerprint = context->active_fingerprint;
	}

	return fingerprint;
}

- (NSString *)fingerprintStringFromFingerprint:(Fingerprint *)fingerprint
{
	char their_hash[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];

	if (fingerprint && fingerprint->fingerprint) {
		otrl_privkey_hash_to_human(their_hash, fingerprint->fingerprint);

		return @(their_hash);
	}

	return nil;
}

- (NSString *)fingerprintForAccountName:(NSString *)accountName
							   protocol:(NSString *)protocol
{
	CheckParamaterForNilValueR(accountName, nil)
	CheckParamaterForNilValueR(protocol, nil)

	__block NSString *fingerprint = nil;

	[self performSyncOperationOnMainQueue:^{
		char our_hash[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];

		otrl_privkey_fingerprint(_userState, our_hash, [accountName UTF8String], [protocol UTF8String]);

		fingerprint = @(our_hash);
	}];

	return fingerprint;
}

- (NSString *)activeFingerprintForUsername:(NSString *)username
							   accountName:(NSString *)accountName
								  protocol:(NSString *)protocol
{
	CheckParamaterForNilValueR(username, nil)
	CheckParamaterForNilValueR(accountName, nil)
	CheckParamaterForNilValueR(protocol, nil)

	__block NSString *activeFingerprint = nil;

	[self performSyncOperationOnMainQueue:^{
		Fingerprint *fingerprint = [self internalActiveFingerprintForUsername:username accountName:accountName protocol:protocol];

		if (fingerprint) {
			activeFingerprint = [self fingerprintStringFromFingerprint:fingerprint];
		}
	}];

	return activeFingerprint;
}

- (BOOL)activeFingerprintIsVerifiedForUsername:(NSString *)username
								   accountName:(NSString *)accountName
									  protocol:(NSString *)protocol
{
	CheckParamaterForNilValueR(username, NO)
	CheckParamaterForNilValueR(accountName, NO)
	CheckParamaterForNilValueR(protocol, NO)

	__block BOOL verified = NO;

	[self performSyncOperationOnMainQueue:^{
		Fingerprint *fingerprint = [self internalActiveFingerprintForUsername:username accountName:accountName protocol:protocol];

		if (fingerprint) {
			if (fingerprint->trust) {
				if (otrl_context_is_fingerprint_trusted(fingerprint)) {
					verified = YES;
				}
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
	CheckParamaterForNilValue(username)
	CheckParamaterForNilValue(accountName)
	CheckParamaterForNilValue(protocol)

	[self performAsyncOperationOnMainQueue:^{
		Fingerprint *fingerprint = [self internalActiveFingerprintForUsername:username accountName:accountName protocol:protocol];

		if (fingerprint) {
			[self setVerificationForFingerprint:fingerprint verified:verified];

			[self postDelegateVerifiedStateChangedForUsername:username accountName:accountName protocol:protocol verified:verified];
		}
	}];
}

- (void)setFingerprintVerificationForConcreteObject:(OTRKitConcreteObject *)fingerprint verified:(BOOL)verified
{
	CheckParamaterForNilValue(fingerprint)

	[self performAsyncOperationOnMainQueue:^{
		Fingerprint *fingerprintReference = [fingerprint fingerprint];

		if (fingerprintReference) {
			/* Set the fingerprint on our reference fingerprint */
			[self setVerificationForFingerprint:fingerprintReference verified:verified];

			/* Compare our reference fingerprint against that of the user */
			Fingerprint *activeFingerprintForUser = [self internalActiveFingerprintForUsername:[fingerprint username] accountName:[fingerprint accountName] protocol:[fingerprint protocol]];

			if (fingerprintReference == activeFingerprintForUser) {
				[self postDelegateVerifiedStateChangedForUsername:[fingerprint username] accountName:[fingerprint accountName] protocol:[fingerprint protocol] verified:verified];
			}
		}
	}];
}

- (void)setVerificationForFingerprint:(Fingerprint *)fingerprint verified:(BOOL)verified
{
	const char *newTrust = nil;

	if (verified) {
		newTrust = [@"verified" UTF8String];
	}

	otrl_context_set_trust(fingerprint, newTrust);

	[self writeFingerprints];
}

- (void)postDelegateVerifiedStateChangedForUsername:(NSString *)username accountName:(NSString *)accountName protocol:(NSString *)protocol verified:(BOOL)verified
{
	[self performAsyncOperationOnMainQueue:^{
		[[self delegate] otrKit:self fingerprintIsVerifiedStateChangedForUsername:username accountName:accountName protocol:protocol verified:verified];
	}];
}

- (void)writeFingerprints
{
	NSString *path = [self fingerprintsPath];

	FILE *storef = fopen([path UTF8String], "wb");

	if (storef == NULL) {
		return;
	}

	otrl_privkey_write_fingerprints_FILEp(_userState, storef);

	fclose(storef);

	[self postFingerprintsDidChangeNotification];
}

- (void)postMessageStateDidChangeNotification
{
	[self performAsyncOperationOnMainQueue:^{
		[[NSNotificationCenter defaultCenter] postNotificationName:OTRKitMessageStateDidChangeNotification object:self];
	}];
}

- (void)postFingerprintsDidChangeNotification
{
	[self performAsyncOperationOnMainQueue:^{
		[[NSNotificationCenter defaultCenter] postNotificationName:OTRKitListOfFingerprintsDidChangeNotification object:[OTRKit sharedInstance]];
	}];
}

- (OTRKitMessageState)messageStateForUsername:(NSString *)username
								  accountName:(NSString *)accountName
									 protocol:(NSString *)protocol
{
	CheckParamaterForNilValueR(username, OTRKitMessageStatePlaintext)
	CheckParamaterForNilValueR(accountName, OTRKitMessageStatePlaintext)
	CheckParamaterForNilValueR(protocol, OTRKitMessageStatePlaintext)

	__block OTRKitMessageState messageState = OTRKitMessageStatePlaintext;

	[self performSyncOperationOnMainQueue:^{
		ConnContext *context = [self contextForUsername:username accountName:accountName protocol:protocol];

		if (context) {
			switch (context->msgstate) {
				case OTRL_MSGSTATE_ENCRYPTED:
				{
					messageState = OTRKitMessageStateEncrypted;

					break;
				}
				case OTRL_MSGSTATE_FINISHED:
				{
					messageState = OTRKitMessageStateFinished;

					break;
				}
				case OTRL_MSGSTATE_PLAINTEXT:
				{
					messageState = OTRKitMessageStatePlaintext;

					break;
				}
			}
		}
	}];

	return messageState;
}

- (OTRKitOfferState)offerStateForUsername:(NSString *)username
							  accountName:(NSString *)accountName
								 protocol:(NSString *)protocol
{
	CheckParamaterForNilValueR(username, OTRKitOfferStateNone)
	CheckParamaterForNilValueR(accountName, OTRKitOfferStateNone)
	CheckParamaterForNilValueR(protocol, OTRKitOfferStateNone)

	__block OTRKitOfferState offerState = OTRKitOfferStateNone;

	[self performSyncOperationOnMainQueue:^{
		ConnContext *context = [self contextForUsername:username accountName:accountName protocol:protocol];

		if (context) {
			switch (context->otr_offer) {
				case OFFER_NOT:
				{
					offerState = OTRKitOfferStateNone;

					break;
				}
				case OFFER_ACCEPTED:
				{
					offerState = OTRKitOfferStateAccepted;

					break;
				}
				case OFFER_REJECTED:
				{
					offerState = OTRKitOfferStateRejected;

					break;
				}
				case OFFER_SENT:
				{
					offerState = OTRKitOfferStateSent;

					break;
				}
			}
		}
	}];
	
	return offerState;
}

- (OTRKitPolicy)otrPolicy
{
	if (_otrPolicy) {
		return _otrPolicy;
	} else {
		return OTRKitPolicyDefault;
	}
}

- (OtrlPolicy)otrlPolicy
{
	switch ([self otrPolicy]) {
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

- (NSArray *)requestAllFingerprints
{
	__block NSArray *allFingerprints = nil;

	[self performSyncOperationOnMainQueue:^{
		NSMutableArray *fingerprintsArray = [NSMutableArray array];

		ConnContext *context = _userState->context_root;

		while (context) {
			Fingerprint *fingerprint = context->fingerprint_root.next;

			while (fingerprint) {
				/* Gather information about the current fingerprint. */
				NSString *fingerprintString = [self fingerprintStringFromFingerprint:fingerprint];

				NSString *username = @(context->username);
				NSString *accountName = @(context->accountname);

				NSString *protocol = @(context->protocol);

				BOOL isTrusted = otrl_context_is_fingerprint_trusted(fingerprint);

				/* Build a concrete object around the information gathered */
				OTRKitConcreteObject *resultObject = [OTRKitConcreteObject new];

				[resultObject setUsername:username];
				[resultObject setAccountName:accountName];

				[resultObject setProtocol:protocol];

				[resultObject setFingerprint:fingerprint];
				[resultObject setFingerprintString:fingerprintString];

				[resultObject setFingerprintIsTrusted:isTrusted];

				[fingerprintsArray addObject:resultObject];

				/* Move on to the next fingerprint in the chain */
				fingerprint = fingerprint->next;
			}

			context = context->next;
		}

		allFingerprints = [fingerprintsArray copy];
	}];

	return allFingerprints;
}

- (void)deleteFingerprint:(NSString *)fingerprintString
				 username:(NSString *)username
			  accountName:(NSString *)accountName
				 protocol:(NSString *)protocol
{
	CheckParamaterForNilValue(fingerprintString)

	CheckParamaterForNilValue(username)
	CheckParamaterForNilValue(accountName)
	CheckParamaterForNilValue(protocol)

	[self performAsyncOperationOnMainQueue:^{
		ConnContext *context = [self contextForUsername:username accountName:accountName protocol:protocol];

		if (context == NULL) {
			return;
		}

		Fingerprint *fingerprint = nil;

		Fingerprint *currentFingerprint = context->fingerprint_root.next;

		while (currentFingerprint) {
			char their_hash[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];

			otrl_privkey_hash_to_human(their_hash, currentFingerprint->fingerprint);

			NSString *currentFingerprintString = @(their_hash);

			if ([currentFingerprintString isEqualToString:fingerprintString]) {
				fingerprint = currentFingerprint;
			} else {
				currentFingerprint = currentFingerprint->next;
			}
		}

		[self maybeDeleteFingerprint:fingerprint username:username accountName:accountName protocol:protocol];
	}];
}

- (void)deleteFingerprintWithConcreteObject:(OTRKitConcreteObject *)fingerprint
{
	CheckParamaterForNilValue(fingerprint)

	[self performAsyncOperationOnMainQueue:^{
		[self maybeDeleteFingerprint:[fingerprint fingerprint] username:[fingerprint username] accountName:[fingerprint accountName] protocol:[fingerprint protocol]];
	}];
}

- (void)maybeDeleteFingerprint:(Fingerprint *)fingerprint username:(NSString *)username accountName:(NSString *)accountName protocol:(NSString *)protocol
{
	Fingerprint *activeFingerprintForUser = [self internalActiveFingerprintForUsername:username accountName:accountName protocol:protocol];

	if (fingerprint == activeFingerprintForUser) {
		; // Cannot delete the active fingerprint...
	} else {
		[self deleteFingerprint:fingerprint];
	}
}

- (void)deleteFingerprint:(Fingerprint *)fingerprint
{
	if (fingerprint) {
		otrl_context_forget_fingerprint(fingerprint, 0);

		[self writeFingerprints];
	}
}

- (void)requestSymmetricKeyForUsername:(NSString *)username
						   accountName:(NSString *)accountName
							  protocol:(NSString *)protocol
								forUse:(NSUInteger)use
							   useData:(NSData *)useData
							completion:(void (^)(NSData *key, NSError *error))completion
{
	CheckParamaterForNilValue(username)
	CheckParamaterForNilValue(accountName)
	CheckParamaterForNilValue(protocol)

	CheckParamaterForNilValue(useData)

	[self performAsyncOperationOnMainQueue:^{
		ConnContext *context = [self contextForUsername:username accountName:accountName protocol:protocol];

		if (context == NULL) {
			return;
		}

		uint8_t *symKey = malloc(OTRL_EXTRAKEY_BYTES * sizeof(uint8_t));

		gcry_error_t err = otrl_message_symkey([self userState], &ui_ops, NULL, context, (unsigned int)use, useData.bytes, useData.length, symKey);

		NSData *keyData = nil;

		NSError *error = nil;

		if (err == gcry_err_code(GPG_ERR_NO_ERROR)) {
			keyData = [[NSData alloc] initWithBytes:symKey length:OTRL_EXTRAKEY_BYTES];
		} else {
			error = [self errorForGPGError:err];
		}

		if (completion) {
			completion(keyData, error);
		}
	}];
}

- (void) initiateSMPForUsername:(NSString *)username
					accountName:(NSString *)accountName
					   protocol:(NSString *)protocol
						 secret:(NSString *)secret
{
	CheckParamaterForNilValue(username)
	CheckParamaterForNilValue(accountName)
	CheckParamaterForNilValue(protocol)

	CheckParamaterForNilValue(secret)

	[self performAsyncOperationOnMainQueue:^{
		ConnContext *context = [self contextForUsername:username accountName:accountName protocol:protocol];

		if (context == NULL) {
			return;
		}

		otrl_message_initiate_smp([self userState], &ui_ops, NULL, context, (const unsigned char*)[secret UTF8String], [secret lengthOfBytesUsingEncoding:NSUTF8StringEncoding]);
	}];
}

- (void) initiateSMPForUsername:(NSString *)username
					accountName:(NSString *)accountName
					   protocol:(NSString *)protocol
					   question:(NSString *)question
						 secret:(NSString *)secret
{
	CheckParamaterForNilValue(username)
	CheckParamaterForNilValue(accountName)
	CheckParamaterForNilValue(protocol)

	CheckParamaterForNilValue(question)
	CheckParamaterForNilValue(secret)

	[self performAsyncOperationOnMainQueue:^{
		ConnContext *context = [self contextForUsername:username accountName:accountName protocol:protocol];

		if (context == NULL) {
			return;
		}

		otrl_message_initiate_smp_q([self userState], &ui_ops, NULL, context, [question UTF8String], (const unsigned char*)[secret UTF8String], [secret lengthOfBytesUsingEncoding:NSUTF8StringEncoding]);
	}];
}

- (void)respondToSMPForUsername:(NSString *)username
					accountName:(NSString *)accountName
					   protocol:(NSString *)protocol
						 secret:(NSString *)secret
{
	CheckParamaterForNilValue(username)
	CheckParamaterForNilValue(accountName)
	CheckParamaterForNilValue(protocol)

	CheckParamaterForNilValue(secret)

	[self performAsyncOperationOnMainQueue:^{
		ConnContext *context = [self contextForUsername:username accountName:accountName protocol:protocol];

		if (context == NULL) {
			return;
		}

		otrl_message_respond_smp([self userState], &ui_ops, NULL, context, (const unsigned char*)[secret UTF8String], [secret lengthOfBytesUsingEncoding:NSUTF8StringEncoding]);
	}];
}

- (void)abortSMPForUsername:(NSString *)username
				accountName:(NSString *)accountName
				   protocol:(NSString *)protocol
{
	CheckParamaterForNilValue(username)
	CheckParamaterForNilValue(accountName)
	CheckParamaterForNilValue(protocol)

	[self performAsyncOperationOnMainQueue:^{
		ConnContext *context = [self contextForUsername:username accountName:accountName protocol:protocol];

		if (context == NULL) {
			return;
		}

		otrl_message_abort_smp([self userState], &ui_ops, NULL, context);
	}];
}

- (void)performAsyncOperationOnMainQueue:(dispatch_block_t)block
{
	if ([NSThread isMainThread]) {
		block();
	} else {
		dispatch_async([self internalQueue], block);
	}
}

- (void)performSyncOperationOnMainQueue:(dispatch_block_t)block
{
	if ([NSThread isMainThread]) {
		block();
	} else {
		dispatch_sync([self internalQueue], block);
	}
}

- (NSString *)rightPortionOfAccountName:(NSString *)accountName
{
	CheckParamaterForNilValueR(accountName, nil)

	NSString *separatorSequence = [self accountNameSeparator];

	NSAssert(([separatorSequence length] > 0), @"Bad -accountNameSeparator value");

	NSRange sequenceRange = [accountName rangeOfString:separatorSequence options:NSBackwardsSearch];

	NSInteger sliceRange = (sequenceRange.location + [separatorSequence length]);

	NSAssert((sliceRange > 0), @"Bad accountName value");
	NSAssert((sliceRange < [accountName length]), @"Bad accountName value");
	NSAssert((sequenceRange.location != NSNotFound), @"Bad accountName value");

	NSString *username = [accountName substringFromIndex:sliceRange];

	return username;
}

- (NSString *)leftPortionOfAccountName:(NSString *)accountName
{
	CheckParamaterForNilValueR(accountName, nil)

	NSString *separatorSequence = [self accountNameSeparator];

	NSAssert(([separatorSequence length] > 0), @"Bad -accountNameSeparator value");

	NSRange sequenceRange = [accountName rangeOfString:separatorSequence options:NSBackwardsSearch];

	NSInteger sliceRange = sequenceRange.location;

	NSAssert((sliceRange > 0), @"Bad accountName value");
	NSAssert((sliceRange != NSNotFound), @"Bad accountName value");
	
	NSString *username = [accountName substringToIndex:sliceRange];
	
	return username;
}

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
