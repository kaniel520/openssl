//
//  KAESWrapper.h
//  opensslDemo
//
//  Created by Mac on 14-6-27.
//  Copyright (c) 2014年 FengYingOnline. All rights reserved.
//

#import <Foundation/Foundation.h>

// 加密类型
typedef NS_ENUM(NSInteger, AES_Encrypt_Bits_Type)
{
    AES_Encrypt_Bits128 = 128,
    AES_Encrypt_Bits256 = 256,
};


// 加密还是解密
typedef NS_ENUM(NSInteger, AES_Encypt_Type)
{
    AES_Encrypt_Type_Encrypt = 1,
    AES_ENcrypt_Type_Decrypt = 0
};

/// AES编解码的封装
@interface KAESWrapper : NSObject

// encrypt
/**
 * src:需要加密的源数据
 * key:加密key
 * bits:加密位数类型
 * return:加密后密文 返回nil加密失败
 */
+ (NSData*)encryptNSData:(NSData*)src withKey:(NSString*)key andBits:(int)bits;

// decrypt
/**
 * src:需要解密的源数据
 * key:解密key
 * bits:解密位数类型
 * return:解密数据 返回nil解密失败
 */
+ (NSData*)decryptNSData:(NSData*)src withKey:(NSString*)key andBits:(int)bits;


// 加密解密
/**
 * src:需要解密的源数据
 * key:解密key
 * bits:解密位数类型
 * encryptType:加密还是解密
 * return:解密数据 返回nil解密失败
 */
+ (NSData*)encryptNSDataCFB128:(NSData*)src withKey:(NSString*)key andBits:(int)bits isEncryptOrDecrypt:(int)encryptType;

// 加密解密
/**
 * src:需要解密的源数据
 * key:解密key
 * bits:解密位数类型
 * encryptType:加密还是解密
 * customIV:自定义向量
 * return:解密数据 返回nil解密失败
 */
+ (NSData*)encryptNSDataCFB8:(NSData*)src withKey:(NSString*)key andBits:(int)bits isEncryptOrDecrypt:(int)encryptType customIV:(NSString *)customIV;

@end
