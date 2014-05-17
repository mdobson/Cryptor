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

- (void)generateKeyPair;

@end

@implementation MSDViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    [self generateKeyPair];
	// Do any additional setup after loading the view, typically from a nib.
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

static const uint8_t publicKeyIdentifier[] = "com.apple.sample.publickey";

static const uint8_t privateKeyIdentifier[] = "com.apple.sample.privatekey";

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
    
    if (status == errSecSuccess) {
        NSLog(@"No generation error");
    }
    
    if (publicKey) {
        NSLog(@"public:%@", publicKey);
        CFRelease(publicKey);
    }
    
    if (privateKey) {
        NSLog(@"private:%@", privateKey);
        CFRelease(privateKey);
    }
    
    [self retrieveKeys];
}


-(void)retrieveKeys {
    OSStatus status = noErr;
    SecKeyRef publicKey = NULL;
    
    NSData * publicTag = [NSData dataWithBytes:publicKeyIdentifier length:strlen((const char *) publicKeyIdentifier)];
    
    NSMutableDictionary *keyQuery = [[NSMutableDictionary alloc] init];
    [keyQuery setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [keyQuery setObject:(id)publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    [keyQuery setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyQuery setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    status = SecItemCopyMatching((__bridge CFDictionaryRef)keyQuery, &publicKey);
    
    if (status == errSecSuccess) {
        size_t keySize = SecKeyGetBlockSize(publicKey);
        NSData *keyData = [NSData dataWithBytes:publicKey length:keySize];
        self.textView.text = [keyData base64EncodedStringWithOptions:kNilOptions];
    } else {
        NSLog(@"ERR");
    }
}

@end
