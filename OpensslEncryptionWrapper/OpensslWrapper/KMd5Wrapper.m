//
//  KMd5Wrapper.m
//  opensslDemo
//
//  Created by Mac on 14-6-27.
//  Copyright (c) 2014年 FengYingOnline. All rights reserved.
//
// openssl version:openssl-1.0.1h
#import "KMd5Wrapper.h"
#import <openssl/md5.h>

@implementation KMd5Wrapper

+(NSString*)generateMd5FromNSString:(NSString *)src
{
    return [KMd5Wrapper generateMd5FromNSData:[NSData dataWithBytes:[[src dataUsingEncoding : NSUTF8StringEncoding ] bytes] length:src.length]];
}


+ (NSString*)generateMd5FromNSData:(NSData *)src
{
    return [KMd5Wrapper generateMd5FromUnsignedChar:(unsigned char *)[src bytes] length:src.length];
}

+ (NSString*)generateMd5FromUnsignedChar:(unsigned char *)src length:(NSInteger)length;
{
    // 输入参数 1 ：要生成 md5 值的字符串， NSString-->uchar*
    unsigned char *inStrg = src;
    // 输入参数 2 ：字符串长度
    unsigned long lngth = length;
    // 输出参数 3 ：要返回的 md5 值， MD5_DIGEST_LENGTH 为 16bytes ， 128 bits
    unsigned char result[ MD5_DIGEST_LENGTH ];
    // 临时 NSString 变量，用于把 uchar* 组装成可以显示的字符串： 2 个字符一 byte 的 16 进制数
    NSMutableString *outStrg = [ NSMutableString string ];
    // 调用 OpenSSL 函数
    MD5 (inStrg, lngth, result);
    unsigned int i;
    for (i = 0 ; i < MD5_DIGEST_LENGTH ; i++) {
        [outStrg appendFormat : @"%02x" , result[i]];
    }
    
    return outStrg;
}

@end
