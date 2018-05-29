/* *********************************************************************
 *
 *        Copyright (c) 2015 - 2018 Codeux Software, LLC
 *     Please see ACKNOWLEDGEMENT for additional information.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  * Neither the name of "Codeux Software, LLC", nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *********************************************************************** */

//
//  OTRTLV.h
//  OTRKit
//
//  Created by Christopher Ballinger on 3/19/14.
//
//

typedef NS_ENUM(uint16_t, OTRTLVType) {
    /* This is just padding for the encrypted message, and should be ignored. */
    OTRTLVTypePadding = 0x0000,

    /* The sender has thrown away his OTR session keys with you */
    OTRTLVTypeDisconnected =  0x0001,

    /* The message contains a step in the Socialist Millionaires' Protocol. */
    OTRTLVTypeSMP1 =          0x0002,
    OTRTLVTypeSMP2 =          0x0003,
    OTRTLVTypeSMP3 =          0x0004,
    OTRTLVTypeSMP4 =          0x0005,
    OTRTLVTypeSMP_ABORT =     0x0006,

    /* Like OTRL_TLV_SMP1, but there's a question for the buddy at the
         * beginning */
    OTRTLVTypeSMP1Question =  0x0007,

    /* Tell the application the current "extra" symmetric key */
    /* XXX: Document this in the protocol spec:
     * The body of the TLV will begin with a 4-byte indication of what this
     * symmetric key will be used for (file transfer, voice encryption,
     * etc.).  After that, the contents are use-specific (which file, etc.).
     * There are no currently defined uses. */
    OTRTLVTypeSymmetricKey =  0x0008,

    /* For OTRDATA, see
     https://dev.guardianproject.info/projects/gibberbot/wiki/OTRDATA_Specifications */
    OTRTLVTypeDataRequest = 0x100,
    OTRTLVTypeDataResponse = 0x101
};

NS_ASSUME_NONNULL_BEGIN

@interface OTRTLV : NSObject
@property (nonatomic, copy) NSData *data;
@property (nonatomic) OTRTLVType type;

/**
 * @param type TLV type
 * @param data this data must be of length shorter than UINT16_MAX bytes
 */
- (nullable instancetype)initWithType:(OTRTLVType)type data:(NSData *)data NS_DESIGNATED_INITIALIZER;

/**
 * returns NO if data.length > UINT16_MAX
 */
@property (getter=isValidLength, readonly) BOOL validLength;
@end

NS_ASSUME_NONNULL_END
