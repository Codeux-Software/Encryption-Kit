//
//  OTRTLV.m
//  OTRKit
//
//  Created by Christopher Ballinger on 3/19/14.
//
//

#import "OTRTLV.h"

NS_ASSUME_NONNULL_BEGIN

@implementation OTRTLV

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-designated-initializers"
- (instancetype)init
{
	return nil;
}
#pragma clang diagnostic pop

- (nullable instancetype)initWithType:(OTRTLVType)type data:(NSData *)data
{
	if (data == nil || data.length > UINT16_MAX) {
		return nil;
	}

    if ((self = [super init])) {
		self.type = type;

		self.data = data;
    }

    return self;
}

- (BOOL)isValidLength
{
    if (self.data == nil || self.data.length > UINT16_MAX) {
        return NO;
	} else {
		return YES;
	}
}

@end

NS_ASSUME_NONNULL_END
