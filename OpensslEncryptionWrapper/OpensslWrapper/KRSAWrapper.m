//
//  KRSAWrapper.m
//  opensslDemo
//
//  Created by Mac on 14-6-27.
//  Copyright (c) 2014年 FengYingOnline. All rights reserved.
//
// openssl version:openssl-1.0.1h
#import "KRSAWrapper.h"
#import <openssl/pem.h>
#import <openssl/rsa.h>
#import <openssl/pkcs7.h>
#import "KAESWrapper.h"
/// RSA加密封装

@implementation KRSAWrapper

+ (NSData*)encryptNSData:(NSData*)srcData withPublicKeyPath:(NSString*)keyPublicPemFilePath
{
    // 打开公钥文件
    char * pub_key = (char*)keyPublicPemFilePath.UTF8String;
    FILE* pub_fp = fopen(pub_key,"r");
    int nSize = 0;
    unsigned char * pSrc = NULL;
    // 用公钥加密
    unsigned char * pTo = NULL;
    int error = 0;
    #if __has_feature(objc_arc)
    NSMutableData *dataEncrypted  = [[NSMutableData alloc]init];
    #else
        NSMutableData *dataEncrypted  = [[[NSMutableData alloc]init]autorelease];
    #endif
    int nTotalSize = srcData.length;// 数据总大小
    int nCurEncryptSize = 0;
    
    if(pub_fp == NULL){
        NSLog(@"failed to open pub_key file %s!\n", pub_key);
        goto EXIT;
    }
    
    // 从文件中读取公钥
    RSA* rsa1 = RSA_new();
    if(PEM_read_RSA_PUBKEY(pub_fp, &rsa1, NULL, NULL) == NULL){
        printf("unable to read public key!\n");
        goto EXIT;
    }
    fclose(pub_fp);
    
    nSize = RSA_size(rsa1);
    // 用公钥加密
    pTo = malloc(nSize + 1);
    
    pSrc = (unsigned char*)[srcData bytes];


    // 循环加密数据
    do {
        // RSA_PKCS1_PADDING的最大加密长度为 对于2048bit的密钥，　block length = 2048/8 – 11 = 53 字节
        if (nTotalSize > nSize - 11) {
            nCurEncryptSize = nSize - 11;
        }else{
            nCurEncryptSize = nTotalSize;
        }
        
        nTotalSize -= nCurEncryptSize;// 剩余大小
        // 输出的块大小为密钥大小
        error = RSA_public_encrypt(nCurEncryptSize, pSrc, pTo, rsa1, RSA_PKCS1_PADDING);
        if(error == -1 ){
            printf("failed to encrypt\n");
            goto EXIT;
        }
        [dataEncrypted appendBytes:pTo length:nSize];
        memset(pTo, 0, nSize + 1);
        pSrc += nCurEncryptSize;/// 跳到下一未加密位置
        NSLog(@"residue:%d", nTotalSize);
    } while (nTotalSize > 0);
    
EXIT:
    RSA_free(rsa1);
    free(pTo);
    
    return dataEncrypted;
}


+ (NSData*)decryptNSData:(NSData*)srcData withPriveKeyPath:(NSString*)keyPrivePemFilePath
{
    // 打开私钥文件
    char * pub_key = (char*)keyPrivePemFilePath.UTF8String;
    FILE* pub_fp = fopen(pub_key,"r");
    int nSize = 0;
    int len = 0;
    unsigned char * pSrc = NULL;
    unsigned char *pTo = NULL;
    #if __has_feature(objc_arc)
    NSMutableData *dataDecrypted = [[NSMutableData alloc]init];
    #else
    NSMutableData *dataDecrypted = [[[NSMutableData alloc]init]autorelease];
    #endif
    int nTotalSize = srcData.length;
    int nCurDecrtypeSize = 0;// 当前加密大小
    
    if(pub_fp == NULL){
        NSLog(@"failed to open pub_key file %s!\n", pub_key);
        goto EXIT;
    }
    
    // 从文件中读取公钥
    RSA* rsa1 = PEM_read_RSAPrivateKey(pub_fp, NULL, NULL, NULL);
    if(rsa1==NULL){
        printf("unable to read public key!\n");
         goto EXIT;
    }
    fclose(pub_fp);
    
    nSize = RSA_size(rsa1);// 密钥大小
    pSrc = (unsigned char*)[srcData bytes];
    // 私钥解密
    pTo = malloc(nSize + 1);
    
    // 循环解密
    do{
        // 每次解密块大小为密钥块大小
        if (nTotalSize > nSize) {
            nCurDecrtypeSize = nSize;
        }else{
            nCurDecrtypeSize = nTotalSize;
        }
        nTotalSize -= nCurDecrtypeSize;
        memset(pTo, 0, nSize + 1);
        len = RSA_private_decrypt(nCurDecrtypeSize, pSrc, pTo, rsa1, RSA_PKCS1_PADDING);
        if(len == -1 ){
            printf("failed to encrypt\n");
            goto EXIT;
        }
        
        pSrc += nCurDecrtypeSize;
        [dataDecrypted appendBytes:pTo length:len];
        NSLog(@"residue:%d", nTotalSize);
    }while (nTotalSize > 0);
    
EXIT:
    RSA_free(rsa1);
    free(pTo);
    return dataDecrypted;
}

+ (NSData*)decryptNSData:(NSData*)srcData withPriveKeyData:(NSData*)keyPrivateData
{
    
    // 打开私钥文件
    int nSize = 0;
    int len = 0;
    unsigned char * pSrc = NULL;
    unsigned char *pTo = NULL;
#if __has_feature(objc_arc)
    NSMutableData *dataDecrypted = [[NSMutableData alloc]init];
#else
    NSMutableData *dataDecrypted = [[[NSMutableData alloc]init]autorelease];
#endif
    int nTotalSize = srcData.length;
    int nCurDecrtypeSize = 0;// 当前加密大小
    
    if (!keyPrivateData || keyPrivateData.length == 0) {
        NSLog(@"key data nil");
        return nil;
    }

    // 从文件中读取公钥
    RSA* rsa1 = NULL;
    BIO *bio = BIO_new_mem_buf((void *)[keyPrivateData bytes], keyPrivateData.length);
    rsa1 = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    
    if(rsa1==NULL){
        printf("unable to read public key!\n");
        goto EXIT;
    }

    nSize = RSA_size(rsa1);// 密钥大小
    pSrc = (unsigned char*)[srcData bytes];
    // 私钥解密
    pTo = malloc(nSize + 1);
    
    // 循环解密
    do{
        // 每次解密块大小为密钥块大小
        if (nTotalSize > nSize) {
            nCurDecrtypeSize = nSize;
        }else{
            nCurDecrtypeSize = nTotalSize;
        }
        nTotalSize -= nCurDecrtypeSize;
        memset(pTo, 0, nSize + 1);
        len = RSA_private_decrypt(nCurDecrtypeSize, pSrc, pTo, rsa1, RSA_PKCS1_PADDING);
        if(len == -1 ){
            printf("failed to encrypt\n");
            goto EXIT;
        }
        
        pSrc += nCurDecrtypeSize;
        [dataDecrypted appendBytes:pTo length:len];
        NSLog(@"residue:%d", nTotalSize);
    }while (nTotalSize > 0);
    
EXIT:
    RSA_free(rsa1);
    free(pTo);
    return dataDecrypted;
}

+(NSData *)decryptRSAData:(NSData *)enDtata withEncryptedPrivateKeyPath:(NSString *)encryptKeyFilePath decryptFileKey:(NSString *)key
{
    if (enDtata == nil || enDtata.length == 0 || encryptKeyFilePath.length == 0 || key.length == 0) {
        NSLog(@"error parameters");
        return nil;
    }
    
    
    NSData * enRSAKeyPrivate = [NSData dataWithContentsOfFile:encryptKeyFilePath];
    NSData *deRSAKeyPrivate = nil;
    if (enRSAKeyPrivate) {
        deRSAKeyPrivate = [KAESWrapper encryptNSDataCFB128:enRSAKeyPrivate withKey:key andBits:128 isEncryptOrDecrypt:AES_ENcrypt_Type_Decrypt];
    }
    return [KRSAWrapper decryptNSData:enDtata withPriveKeyData:deRSAKeyPrivate];
}

@end
