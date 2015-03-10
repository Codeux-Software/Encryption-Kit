//
//  OTRTLV.m
//  OTRKit
//
//  Created by Christopher Ballinger on 3/19/14.
//
//

#import "OTRTLV.h"

@implementation OTRTLV

- (instancetype)initWithType:(OTRTLVType)type data:(NSData *)data
{
	if (data == nil || [data length] > UINT16_MAX) {
		return nil;
	}

    if ((self = [super init])) {
		[self setType:type];
		[self setData:data];
    }

    return self;
}

- (BOOL)isValidLength
{
    if (_data == nil || [_data length] > UINT16_MAX) {
        return NO;
	} else {
		return YES;
	}
}

@end
