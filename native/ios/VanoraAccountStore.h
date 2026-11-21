#import <Foundation/Foundation.h>
#import <Mobile/Mobile.h>

NS_ASSUME_NONNULL_BEGIN
@interface VanoraAccountStore : NSObject <MobileStore>
- (instancetype)initWithProfile:(NSString *)profile;
@end
NS_ASSUME_NONNULL_END
