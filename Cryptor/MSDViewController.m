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

static const UInt8 publicKeyIdentifier[] = "com.apple.sample.publickey\0";

static const UInt8 privateKeyIdentifier[] = "com.apple.sample.privatekey\0";

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
    [publicKeyAttr setObject:publicTag forKey:(__bridge id)kSecPublicKeyAttrs];
    
    status = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr, &publicKey, &privateKey);
    
    if (status == errSecSuccess) {
        NSLog(@"No generation error");
    }
    size_t keySize = SecKeyGetBlockSize(publicKey);
    NSData *keyData = [NSData dataWithBytes:publicKey length:keySize];
    self.textView.text = [keyData base64EncodedStringWithOptions:kNilOptions];
    
    if (publicKey) {
        NSLog(@"public:%@", publicKey);
        CFRelease(publicKey);
    }
    
    if (privateKey) {
        NSLog(@"private:%@", privateKey);
        CFRelease(privateKey);
    }
}

@end
