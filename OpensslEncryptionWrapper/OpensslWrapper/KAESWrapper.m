//
//  KAESWrapper.m
//  opensslDemo
//
//  Created by Mac on 14-6-27.
//  Copyright (c) 2014年 FengYingOnline. All rights reserved.
//
// openssl version:openssl-1.0.1h
#import "KAESWrapper.h"
#import <openssl/aes.h>

@implementation KAESWrapper

+ (NSData*)encryptNSData:(NSData*)src withKey:(NSString*)key andBits:(int)bits
{
    AES_KEY aesKey;
    int error = 0;
    if ((error = AES_set_encrypt_key((const unsigned char*)key.UTF8String, bits, &aesKey)) < 0){
        NSLog(@"=== 设置AES加密key失败.error:%d", error);
        return nil;
    }
    unsigned char *srcData = (unsigned char *)[src bytes];
    int nCount = src.length;
    nCount = src.length % AES_BLOCK_SIZE == 0 ? src.length : (src.length / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
    unsigned char *pSrc = malloc(nCount);
    memset(pSrc, 0, nCount);
    memcpy(pSrc, srcData, src.length);

    unsigned char *outData = (unsigned char*)malloc(AES_BLOCK_SIZE+1);
    memset(outData, 0, AES_BLOCK_SIZE+1);
    int nTotalSize = src.length;
    int nCurEncryptSize = 0;
    NSMutableData * destData = [[NSMutableData alloc]init];//WithBytes:outData length:src.length];
    
    do{
        if (nTotalSize > AES_BLOCK_SIZE) {
            nCurEncryptSize = AES_BLOCK_SIZE;
        }else{
            nCurEncryptSize = nTotalSize;
        }
        nTotalSize -= nCurEncryptSize;
        AES_encrypt(pSrc, outData, &aesKey);
        [destData appendBytes:outData length:AES_BLOCK_SIZE];
        pSrc += nCurEncryptSize;
        
    }while (nTotalSize > 0);
    
    free(outData);
    free(pSrc);

    return destData;
}


+ (NSData*)decryptNSData:(NSData*)src withKey:(NSString*)key andBits:(int)bits;
{

    AES_KEY aesKey;
    int error = 0;
    if ((error = AES_set_decrypt_key((const unsigned char*)key.UTF8String, bits, &aesKey)) < 0){
        NSLog(@"=== 设置AES加密key失败.error:%d", error);
        return nil;
    }
    
    unsigned char *srcData = (unsigned char *)[src bytes];
    unsigned char *outData = (unsigned char*)malloc(AES_BLOCK_SIZE+1);
    memset(outData, 0, AES_BLOCK_SIZE + 1);
    int nTotalSize = src.length;
    int nCurEncryptSize = 0;
#if __has_feature(objc_arc)
    NSMutableData * destData = [[NSMutableData alloc]init];
#else
    NSMutableData * destData = [[[NSMutableData alloc]init]autorelease];
#endif
    do{
        if (nTotalSize > AES_BLOCK_SIZE) {
            nCurEncryptSize = AES_BLOCK_SIZE;
        }else{
            nCurEncryptSize = nTotalSize;
        }
        nTotalSize -= nCurEncryptSize;
        AES_decrypt(srcData, outData, &aesKey);
        [destData appendBytes:outData length:AES_BLOCK_SIZE];
        srcData += nCurEncryptSize;
        
    }while (nTotalSize > 0);
    
    free(outData);
    
    return destData;
}

+ (NSData*)encryptNSDataCFB128:(NSData*)src withKey:(NSString*)key andBits:(int)bits isEncryptOrDecrypt:(int)encryptType
{
    AES_KEY aesKey;
    int error = 0;
#if __has_feature(objc_arc)
    NSMutableData * destData = [[NSMutableData alloc]init];
#else
    NSMutableData * destData = [[[NSMutableData alloc]init]autorelease];
#endif
    // 补全密钥
    if (key.length < 16) {
        int needSize = 16 - key.length;
        
        NSString * temp = @"1234567898765432";
        NSRange range;
        range.location = 0;
        range.length = needSize;
        key = [key stringByAppendingString:[temp substringWithRange:range]];
    }
    
    error = AES_set_encrypt_key((const unsigned char *)key.UTF8String, bits, &aesKey);
    if (error < 0){
        NSLog(@"=== 设置AES加密key失败.error:%d", error);
        return nil;
    }
    
    unsigned char *srcData = (unsigned char *)[src bytes];
    
    int nOutDataSize = src.length + 1;
    unsigned char *outData = (unsigned char*)malloc(nOutDataSize);
    memset(outData, 0, src.length + 1);

    unsigned char iv[AES_BLOCK_SIZE] = {'1','3','6','9','8','5','2','4','7','6','k','a','n','i','e','l'};
    
    int nBlockCount = 0;

    AES_cfb128_encrypt(srcData, outData, src.length, &aesKey, iv, &nBlockCount, encryptType);
    [destData appendBytes:outData length:src.length ];
    
    free(outData);
    
    return destData;
}


+ (NSData*)encryptNSDataCFB8:(NSData*)src withKey:(NSString*)key andBits:(int)bits isEncryptOrDecrypt:(int)encryptType customIV:(NSString *)customIV
{
    AES_KEY aesKey;
    int error = 0;
#if __has_feature(objc_arc)
    NSMutableData * destData = [[NSMutableData alloc]init];
#else
    NSMutableData * destData = [[[NSMutableData alloc]init]autorelease];
#endif
    // 补全密钥
    if (key.length < 16) {
        int needSize = 16 - key.length;
        
        NSString * temp = @"1234567898765432";
        NSRange range;
        range.location = 0;
        range.length = needSize;
        key = [key stringByAppendingString:[temp substringWithRange:range]];
    }
    
    error = AES_set_encrypt_key((const unsigned char *)key.UTF8String, bits, &aesKey);
    if (error < 0){
        NSLog(@"=== 设置AES加密key失败.error:%d", error);
        return nil;
    }
    
    unsigned char *srcData = (unsigned char *)[src bytes];
    
    int nOutDataSize = src.length + 1;
    unsigned char *outData = (unsigned char*)malloc(nOutDataSize);
    memset(outData, 0, src.length + 1);
    
    unsigned char iv[AES_BLOCK_SIZE] = {'1','3','6','9','8','5','2','4','7','6','k','a','n','i','e','l'};

    if (customIV.length == AES_BLOCK_SIZE) {
        [customIV getBytes:iv maxLength:AES_BLOCK_SIZE usedLength:NULL encoding:NSUTF8StringEncoding options:NSStringEncodingConversionAllowLossy range:NSMakeRange(0, customIV.length) remainingRange:nil];
    }
    
    int nBlockCount = 0;
    
    AES_cfb8_encrypt(srcData, outData, src.length, &aesKey, iv, &nBlockCount, encryptType);
    [destData appendBytes:outData length:src.length ];
    
    free(outData);
    
    return destData;
}

@end





