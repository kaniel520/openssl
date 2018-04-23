//
//  KMd5Wrapper.h
//  opensslDemo
//
//  Created by Mac on 14-6-27.
//  Copyright (c) 2014年 FengYingOnline. All rights reserved.
//

#import <Foundation/Foundation.h>


/// MD5编解码的封装

@interface KMd5Wrapper : NSObject

/** 生成md5标示串 
 * src:需要要校验串
 * return:校验生成的校验值
 */
+ (NSString*)generateMd5FromNSString:(NSString *)src;

/** 生成md5标示串
 * src:需要要校验数据
 * return:校验生成的校验值
 */
+ (NSString*)generateMd5FromNSData:(NSData *)src;

/** 生成md5标示串
 * src:需要要串地址
 * length:长度
 * return:校验生成的校验值
 */
+ (NSString*)generateMd5FromUnsignedChar:(unsigned char *)src length:(NSInteger)length;

@end
