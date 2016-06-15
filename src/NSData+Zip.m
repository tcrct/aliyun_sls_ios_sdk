//
//  NSData+Zip.m
//  Fitness
//
//  Created by liuweitao on 16/6/6.
//  Copyright © 2016年 sythealth. All rights reserved.
//

#import "NSData+Zip.h"
#import <zlib.h>

@implementation NSData (Zip)

- (NSData*)sytZip {
    
    if (self.length == 0) {
        return nil;
    }
    
    z_stream zStream;
    zStream.zalloc = Z_NULL;
    zStream.zfree = Z_NULL;
    zStream.opaque = Z_NULL;
    zStream.avail_in = 0;
    zStream.next_in = 0;
    int status = deflateInit2(&zStream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, (15), 8, Z_DEFAULT_STRATEGY);
    if (status != Z_OK) {
        return nil;
    }
    
    Bytef *bytes = (Bytef*)[self bytes];
    zStream.next_in = bytes;
    zStream.avail_in = (unsigned int)self.length;
    zStream.avail_out = 0;
    zStream.total_out = 0;
    
    NSInteger halfLen = self.length / 2;
    NSMutableData *output = [NSMutableData dataWithLength:halfLen];
    while (zStream.avail_out == 0) {
        if (zStream.total_out >= output.length) {
            [output increaseLengthBy:halfLen];
        }
        zStream.next_out = (Bytef*)[output mutableBytes] + zStream.total_out;
        zStream.avail_out = (unsigned int)([output length] - zStream.total_out);
        status = deflate(&zStream,Z_FINISH);
        
        if (status == Z_STREAM_END) {
            break;
        } else if (status != Z_OK) {
            deflateEnd(&zStream);
            return nil;
        }
    }
    [output setLength:zStream.total_out];
    deflateEnd(&zStream);
    return output;
}

- (NSData*)sytUnZip {
    
    if (self.length == 0) {
        return nil;
    }
    
    z_stream zStream;
    zStream.zalloc = Z_NULL;
    zStream.zfree = Z_NULL;
    zStream.opaque = Z_NULL;
    zStream.avail_in = 0;
    zStream.next_in = 0;
    int status = inflateInit2(&zStream, (15+32));
    if (status != Z_OK) {
        return nil;
    }
    
    Bytef *bytes = (Bytef*)[self bytes];
    zStream.next_in = bytes;
    zStream.avail_in = (unsigned int)self.length;
    zStream.avail_out = 0;
    
    NSInteger halfLen = self.length / 2;
    NSMutableData *output = [NSMutableData dataWithLength:self.length+halfLen];
    while (zStream.avail_out == 0) {
        if (zStream.total_out >= output.length) {
            [output increaseLengthBy:halfLen];
        }
        zStream.next_out = (Bytef*)[output mutableBytes] + zStream.total_out;
        zStream.avail_out = (unsigned int)([output length] - zStream.total_out);
        status = inflate(&zStream, Z_NO_FLUSH);
        
        if (status == Z_STREAM_END) {
            break;
        } else if (status != Z_OK) {
            inflateEnd(&zStream);
            return nil;
        }
    }
    [output setLength:zStream.total_out];
    inflateEnd(&zStream);
    return output;
}

@end
