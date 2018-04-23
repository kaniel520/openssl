//
//  main.m
//  opensslDemo
//
//  Created by Mac on 14-6-27.
//  Copyright (c) 2014年 FengYingOnline. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "AppDelegate.h"

#import "KMd5Wrapper.h"
#import "KAESWrapper.h"
#import "KRSAWrapper.h"

//int main(int argc, char * argv[]) {
//    @autoreleasepool {
//        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
//    }
//}


void genEncryptPrivtePem()
{
    NSString *privPath = [[NSBundle mainBundle] pathForResource:@"rsa_prive" ofType:@"pem"];
    NSData *data = [NSData dataWithContentsOfFile:privPath];
    
    NSString *strMd5 = [KMd5Wrapper generateMd5FromNSData:data];
    
    NSData *enData = [KAESWrapper encryptNSDataCFB128:data withKey:@"ka31010058nil" andBits:128 isEncryptOrDecrypt:AES_Encrypt_Type_Encrypt];
    NSString *enDataMd5 = [KMd5Wrapper generateMd5FromNSData:enData];
    
    NSData *deData = [KAESWrapper encryptNSDataCFB128:enData withKey:@"ka31010058nil" andBits:128 isEncryptOrDecrypt:AES_ENcrypt_Type_Decrypt];
    NSString *strMd52 = [KMd5Wrapper generateMd5FromNSData:deData];
//    strMd5 = [KMd5Wrapper generateMd5FromNSData:deData];
    if ([strMd5 isEqualToString:strMd52]) {
        NSString *path  = [[NSBundle mainBundle] pathForResource:@"rsa_enprivate" ofType:@"pem"];
        NSArray *arr = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        path = [arr objectAtIndex:0];
        path = [path stringByAppendingPathComponent:@"rsa_enprivate.pem"];
        [enData writeToFile:path atomically:YES];
        
        NSString *fileDataMd5 = [KMd5Wrapper generateMd5FromNSData:deData];
        NSData *dataFilePath = [NSData dataWithContentsOfFile:path];
        
        NSString *fileDataMd52 = [KMd5Wrapper generateMd5FromNSData:dataFilePath];
        
        NSData *srcData = [@"hello" dataUsingEncoding:NSUTF8StringEncoding];
        NSString *md5 =[KMd5Wrapper generateMd5FromNSData:srcData];
        NSString *publicPath = [[NSBundle mainBundle] pathForResource:@"rsa_public" ofType:@"pem"];
        NSData *enRSAData = [KRSAWrapper encryptNSData:srcData withPublicKeyPath:publicPath];
        NSData *deRSAData = [KRSAWrapper decryptNSData:enRSAData withPriveKeyData:dataFilePath];
        NSString *md52 =[KMd5Wrapper generateMd5FromNSData:deRSAData];
        
        int iii = 0;
    }
    
    
}
void Md5( NSString *);
void testRSA();
void testMD5AndRSAFile()
{
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *docPath = [paths objectAtIndex:0];
    if (!docPath) return;
    
    NSString *testPath = [docPath stringByAppendingPathComponent:@"test.zip"];
    NSString *testEncryptPath = [docPath stringByAppendingPathComponent:@"testEncrypt"];
    NSString *testDecryptPath = [docPath stringByAppendingPathComponent:@"testDecrypt"];
    
    NSData *testData = [NSData dataWithContentsOfFile:testPath];
    
    // 获取校验码
    NSString *strDataMD5 = [KMd5Wrapper generateMd5FromNSData:testData];
    // 加密
    NSData *aesEncryptData = nil;
    // aes
    //aesEncryptData = [KAESWrapper encryptNSDataCFB128:testData withKey:@"kaniel" andBits:128 isEncryptOrDecrypt:AES_Encrypt_Type_Encrypt];
    
    // rsa
    NSString *publicPath = [[NSBundle mainBundle] pathForResource:@"rsa_public" ofType:@"pem"];
    aesEncryptData = [KRSAWrapper encryptNSData:testData withPublicKeyPath:publicPath];
    
    [aesEncryptData writeToFile:testEncryptPath atomically:YES];
    
    // 解密
    NSData *needToDecryptData = [NSData dataWithContentsOfFile:testEncryptPath];
    NSData *aesDecrypteData = nil;
    
    // aes
    //aesDecrypteData = [KAESWrapper encryptNSDataCFB128:needToDecryptData withKey:@"kaniel" andBits:128 isEncryptOrDecrypt:AES_ENcrypt_Type_Decrypt];
    
    // rsa
    NSString *privPath = [[NSBundle mainBundle] pathForResource:@"rsa_prive" ofType:@"pem"];
    aesDecrypteData = [KRSAWrapper decryptNSData:needToDecryptData withPriveKeyPath:privPath];
    
    
    [aesDecrypteData writeToFile:testDecryptPath atomically:YES];
    // 再次校验
    NSString *strDataMD5Decrypt = [KMd5Wrapper generateMd5FromNSData:aesDecrypteData];
    if ([strDataMD5 isEqualToString:strDataMD5Decrypt]) {
        NSLog(@"校验成功，加密解密成功！");
    }
    
    int ii = 0;
}

void testRSA()
{
    NSLog(@"testRSA");
    NSString *str = @"你好吗靠abc http://www.dataoncemore.com/fdsfsd/12345/";
    NSString *publicPath = [[NSBundle mainBundle] pathForResource:@"rsa_public" ofType:@"pem"];
    NSData *srcData = [str dataUsingEncoding:NSUTF8StringEncoding];
    NSString *strmd5 = [KMd5Wrapper generateMd5FromNSData:srcData];
    
    NSData *encryptData = [KRSAWrapper encryptNSData: srcData withPublicKeyPath:publicPath];
    
    NSString *privPath = [[NSBundle mainBundle] pathForResource:@"rsa_prive" ofType:@"pem"];
    NSData *decryptData = [KRSAWrapper decryptNSData:encryptData withPriveKeyPath:privPath];
    
    NSString *strdecryptMd5 = [KMd5Wrapper generateMd5FromNSData:decryptData];
    if ([strmd5 isEqualToString:strdecryptMd5]) {
        NSLog(@"校验成功，加密解密成功");
    }
    
    NSString *strDe = [[NSString alloc]initWithBytes:[decryptData bytes] length:decryptData.length encoding:NSUTF8StringEncoding]; //[NSString stringWithUTF8String:[decryptData bytes]];
    
    NSLog(@"===de:%@", strDe);
}

int main( int argc, char *argv[]) {
    genEncryptPrivtePem();
   // testMD5AndRSAFile();
    NSString *outStrg = [KMd5Wrapper generateMd5FromNSString:@"12345"];
    outStrg = @"你好吗靠abc http://www.dataoncemore.com/fdsfsd/12345/jdfoasjdfiodhjkzfh;uieaafioeo嘿嘿嘿fjaefoijaidfjds;vjxfiojvidjsfiojdoiagjdsojagieojgaijdklvjiczxjvzj";
//    outStrg = @"hello你";
    int n = outStrg.length;
    NSData *src = [outStrg dataUsingEncoding:NSUTF8StringEncoding];//[NSData dataWithBytes:[[outStrg dataUsingEncoding: NSUTF8StringEncoding]bytes] length:outStrg.length];
//    NSLog(@"== src :%@, str:%@", src, [[NSString alloc ] initWithData:src encoding:NSUTF8StringEncoding]);
//    NSData * data = [KAESWrapper encryptNSData:src withKey:@"kaniel" andBits:AES_Encrypt_Bits128];
//    NSLog(@"== en :%@", data);
//    
//    NSData *data2 = [KAESWrapper decryptNSData:data withKey:@"kaniel" andBits:AES_Encrypt_Bits128];
//    NSString *deStr = [[NSString alloc]initWithBytes:[data2 bytes] length:src.length encoding:NSUTF8StringEncoding];
//     NSLog(@"== de str:%@",deStr);
//    NSLog ( @"md5:%@" ,outStrg);
    NSString *customIV = @"ad/BSYVNLR+ak56m";
    NSData *data4 = [KAESWrapper encryptNSDataCFB8:src withKey:@"kaniel" andBits:128 isEncryptOrDecrypt:AES_Encrypt_Type_Encrypt customIV:customIV];
    NSLog(@"== en :%@", data4);
    NSData *data5 = [KAESWrapper encryptNSDataCFB8:data4 withKey:@"kaniel" andBits:128 isEncryptOrDecrypt:AES_ENcrypt_Type_Decrypt customIV:customIV];
    NSString *deStr = [[NSString alloc]initWithBytes:[data5 bytes] length:data5.length encoding:NSUTF8StringEncoding];
    NSLog(@"== de :%@, str:%@", data5, [[NSString alloc]initWithBytes:[data5 bytes] length:data5.length encoding:NSUTF8StringEncoding]);
//    NSLog ( @"md5:%@" ,outStrg);
    
    NSString *temp = @"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";

    NSData *need = [temp dataUsingEncoding:NSUTF8StringEncoding];
    need = [[NSData alloc]initWithBase64EncodedString:temp options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
    NSString *tt = [[NSString alloc]initWithBytes:[need bytes] length:need.length encoding:NSUTF8StringEncoding];
    
    NSData *deNeed = [KAESWrapper encryptNSDataCFB8:need withKey:@"CM/TTu+yCr+7Ug8e" andBits:128 isEncryptOrDecrypt:AES_ENcrypt_Type_Decrypt customIV:customIV];
    NSString *deNeedStr = [[NSString alloc]initWithBytes:[deNeed bytes] length:deNeed.length encoding:NSUTF8StringEncoding];
    
    testRSA();
    
    int retVal = 0;
    @autoreleasepool {
        retVal = UIApplicationMain (argc, argv, nil , nil );
    }
    

    return retVal;
}


