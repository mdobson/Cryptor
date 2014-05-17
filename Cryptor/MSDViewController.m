//
//  MSDViewController.m
//  Cryptor
//
//  Created by Matthew Dobson on 5/16/14.
//  Copyright (c) 2014 Matthew Dobson. All rights reserved.
//

#import "MSDViewController.h"
#import <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>

@interface MSDViewController ()

@property SecKeyRef public;
@property SecKeyRef private;

- (void)generateKeyPair;

@end

@implementation MSDViewController

const size_t BUFFER_SIZE = 64;
const size_t CIPHER_BUFFER_SIZE = 1024;
const uint32_t PADDING = kSecPaddingNone;
static const uint8_t publicKeyIdentifier[] = "com.apple.sample.publickey\0";
static const uint8_t privateKeyIdentifier[] = "com.apple.sample.privatekey\0";


- (void)viewDidLoad
{
    [super viewDidLoad];
    [self generateKeyPair];
    SecKeyRef publicKey = [self retrievePublicKey];
    SecKeyRef privateKey = [self retrievePrivateKey];
    
    uint8_t *plainBuffer;
    uint8_t *cipherBuffer;
    uint8_t *decryptedBuffer;
    
    const char inputString[] = "Hello, World!";
    int len = strlen(inputString);

    plainBuffer = (uint8_t *)calloc(BUFFER_SIZE, sizeof(uint8_t));
    
    strncpy((char *)plainBuffer, inputString, len);
    NSLog(@"strncpy plainBuffer:%s", plainBuffer);
    
    NSData *encryptedData = [self encryptBuffer:plainBuffer withKey:publicKey];
    
    NSData *decryptedData = [self decryptBuffer:encryptedData withKey:privateKey];
    
    NSLog(@"Decrypted:%@", [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding]);
    
    free(cipherBuffer);
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (void)generateKeyPair{
    OSStatus status = noErr;
    
    NSMutableDictionary *privateKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary *publicKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary *keyPairAttr = [[NSMutableDictionary alloc] init];
    
    NSData * publicTag = [NSData dataWithBytes:publicKeyIdentifier length:strlen((const char *) publicKeyIdentifier)];
    
    NSData * privateTag = [NSData dataWithBytes:privateKeyIdentifier length:strlen((const char *)privateKeyIdentifier)];
    
    SecKeyRef publicKey = NULL;
    SecKeyRef privateKey = NULL;
    
    [keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyPairAttr setObject:[NSNumber numberWithInt:1024] forKey:(__bridge id)kSecAttrKeySizeInBits];
    
    [privateKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [privateKeyAttr setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    
    [publicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [publicKeyAttr setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    
    [keyPairAttr setObject:privateKeyAttr forKey:(__bridge id)kSecPrivateKeyAttrs];
    [keyPairAttr setObject:publicKeyAttr forKey:(__bridge id)kSecPublicKeyAttrs];
    
    status = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr, &publicKey, &privateKey);
    
    if (status != errSecSuccess) {
        NSLog(@"Generation error");
    }
    
    if (publicKey) {
        CFRelease(publicKey);
    }
    
    if (privateKey) {
        CFRelease(privateKey);
    }
}


-(SecKeyRef)retrievePublicKey {
    OSStatus status = noErr;
    SecKeyRef publicKey = NULL;
    
    NSData * publicTag = [NSData dataWithBytes:publicKeyIdentifier length:strlen((const char *) publicKeyIdentifier)];
    
    NSMutableDictionary *keyQuery = [[NSMutableDictionary alloc] init];
    [keyQuery setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [keyQuery setObject:(id)publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    [keyQuery setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyQuery setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    status = SecItemCopyMatching((__bridge CFDictionaryRef)keyQuery, &publicKey);
    
    if (status != errSecSuccess) {
        NSLog(@"ERR");
        return NULL;
    } else {
        return publicKey;
    }
}

-(SecKeyRef)retrievePrivateKey {
    OSStatus status = noErr;
    SecKeyRef privateKey = NULL;
    
    NSData * privateTag = [NSData dataWithBytes:privateKeyIdentifier length:strlen((const char *)privateKeyIdentifier)];
    
    NSMutableDictionary *keyQuery = [[NSMutableDictionary alloc] init];
    [keyQuery setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [keyQuery setObject:(id)privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    [keyQuery setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyQuery setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    status = SecItemCopyMatching((__bridge CFDictionaryRef)keyQuery, &privateKey);
    
    if (status != errSecSuccess) {
        NSLog(@"ERR");
        return NULL;
    } else {
        return privateKey;
    }
}

- (NSData *)encryptBuffer:(uint8_t *)plainBuffer withKey:(SecKeyRef)key {
    OSStatus status = noErr;
    size_t cipherBufferSize = SecKeyGetBlockSize(key);
    uint8_t *cipherBuffer = malloc(cipherBufferSize);
    size_t plainBufferSize = strlen((char *)plainBuffer);
    status = SecKeyEncrypt(key, kSecPaddingPKCS1, plainBuffer, plainBufferSize, cipherBuffer, &cipherBufferSize);
    
    NSData *encryptedData = [NSData dataWithBytes:cipherBuffer length:cipherBufferSize];
    free(cipherBuffer);
    return encryptedData;
}

- (NSData *)decryptBuffer:(NSData *)encryptedData withKey:(SecKeyRef)key{
    OSStatus status = noErr;
    size_t cipherBufferSize = [encryptedData length];
    uint8_t *cipherBuffer = (uint8_t *)[encryptedData bytes];
    size_t plainBufferSize = SecKeyGetBlockSize(key);
    uint8_t *plainBuffer = malloc(plainBufferSize);
    
    //status = SecKeyDecrypt(key, kSecPaddingPKCS1, &cipherBuffer[0], cipherBufferSize, &plainBuffer[0], &plainBufferSize);
    
    if (plainBufferSize < cipherBufferSize) {
        NSLog(@"Issues with buffer sizes. Can't decrypt.");
    }
    
    status = SecKeyDecrypt(key, kSecPaddingPKCS1, cipherBuffer, cipherBufferSize, plainBuffer, &plainBufferSize);
    NSData *decryptedData = [NSData dataWithBytes:plainBuffer length:plainBufferSize];
    free(plainBuffer);
    return decryptedData;
}

@end
