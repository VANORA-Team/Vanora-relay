#import "VanoraAccountStore.h"
#import <Security/Security.h>

@implementation VanoraAccountStore {
    NSString *_profile;
}

- (instancetype)initWithProfile:(NSString *)profile {
    self = [super init];
    if (self) _profile = [profile copy];
    return self;
}

- (NSMutableDictionary *)query {
    return [@{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
              (__bridge id)kSecAttrService: @"org.vanora.relay.account",
              (__bridge id)kSecAttrAccount: _profile} mutableCopy];
}

- (NSString *)load:(NSError **)error {
    NSMutableDictionary *query = [self query];
    query[(__bridge id)kSecReturnData] = @YES;
    CFTypeRef item = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &item);
    if (status == errSecItemNotFound) return @"";
    if (status == errSecSuccess) {
        NSString *value = [[NSString alloc] initWithData:CFBridgingRelease(item) encoding:NSUTF8StringEncoding];
        if (value.length > 0) return value;
        status = errSecDecode;
    }
    if (error) *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
    return @"";
}

- (BOOL)save:(NSString *)value error:(NSError **)error {
    NSMutableDictionary *query = [self query];
    NSData *bytes = [value dataUsingEncoding:NSUTF8StringEncoding];
    if (!bytes) {
        if (error) *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:errSecParam userInfo:nil];
        return NO;
    }
    NSDictionary *attributes = @{(__bridge id)kSecValueData: bytes,
                                 (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly};
    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attributes);
    if (status == errSecItemNotFound) {
        [query addEntriesFromDictionary:attributes];
        status = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
    }
    if (status == errSecSuccess) return YES;
    if (error) *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
    return NO;
}
@end
