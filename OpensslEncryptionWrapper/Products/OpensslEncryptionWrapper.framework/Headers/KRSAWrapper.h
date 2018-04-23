//
//  KRSAWrapper.h
//  opensslDemo
//
//  Created by Mac on 14-6-27.
//  Copyright (c) 2014年 FengYingOnline. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface KRSAWrapper : NSObject

/**
 * srcData:加密数据源
 * keyPublicPemFilePath:公钥文件路径
 * return:返回加密数据
 */
+ (NSData*)encryptNSData:(NSData*)srcData withPublicKeyPath:(NSString*)keyPublicPemFilePath;


/**
 * srcData:解密数据源
 * keyPrivePemFilePath:私钥文件路径
 * return:返回解密数据
 */
+ (NSData*)decryptNSData:(NSData*)srcData withPriveKeyPath:(NSString*)keyPrivePemFilePath;

/**
 * srcData:解密数据源
 * keyPrivateData:私钥文件数据
 * return:返回解密数据
 */
+ (NSData*)decryptNSData:(NSData*)srcData withPriveKeyData:(NSData*)keyPrivateData;

/*
 * enData:need to decrypt data
 * encryptKeyFilePath:the path of key file(use encrypted by AES)
 * key:decrypt the key file
 */
+(NSData *)decryptRSAData:(NSData *)enDtata withEncryptedPrivateKeyPath:(NSString *)encryptKeyFilePath decryptFileKey:(NSString *)key;
@end
