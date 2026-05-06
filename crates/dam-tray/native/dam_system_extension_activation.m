#import <Foundation/Foundation.h>
#import <SystemExtensions/SystemExtensions.h>
#import <dispatch/dispatch.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

typedef NS_ENUM(NSInteger, DAMActivationStatus) {
    DAMActivationStatusWaiting = 0,
    DAMActivationStatusReady = 1,
    DAMActivationStatusNeedsApproval = 2,
    DAMActivationStatusFailed = 3,
    DAMActivationStatusNeedsReboot = 4,
};

static const int DAMActivationReturnReady = 0;
static const int DAMActivationReturnNeedsApproval = 1;
static const int DAMActivationReturnFailed = 2;
static const int DAMActivationReturnInvalidArgument = 3;
static const int DAMActivationReturnTimedOut = 4;
static const int DAMActivationReturnNeedsReboot = 5;

@interface DAMSystemExtensionActivation : NSObject <OSSystemExtensionRequestDelegate>
@property(nonatomic, copy) NSString *bundleIdentifier;
@property(nonatomic, strong) dispatch_semaphore_t semaphore;
@property(nonatomic, strong) OSSystemExtensionRequest *request;
@property(nonatomic, assign) DAMActivationStatus status;
@property(nonatomic, copy) NSString *message;
@property(nonatomic, assign) BOOL completed;
- (instancetype)initWithBundleIdentifier:(NSString *)bundleIdentifier;
@end

static NSMutableArray<DAMSystemExtensionActivation *> *DAMPendingActivations(void) {
    static NSMutableArray<DAMSystemExtensionActivation *> *pending;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        pending = [NSMutableArray array];
    });
    return pending;
}

static DAMSystemExtensionActivation *DAMPendingActivationForBundleIdentifier(NSString *bundleIdentifier) {
    @synchronized(DAMPendingActivations()) {
        for (DAMSystemExtensionActivation *activation in DAMPendingActivations()) {
            if ([activation.bundleIdentifier isEqualToString:bundleIdentifier]) {
                return activation;
            }
        }
    }
    return nil;
}

static void DAMRetainPendingActivation(DAMSystemExtensionActivation *activation) {
    @synchronized(DAMPendingActivations()) {
        NSMutableArray<DAMSystemExtensionActivation *> *pending = DAMPendingActivations();
        NSIndexSet *existing = [pending indexesOfObjectsPassingTest:^BOOL(DAMSystemExtensionActivation *candidate, NSUInteger idx, BOOL *stop) {
            (void)idx;
            if ([candidate.bundleIdentifier isEqualToString:activation.bundleIdentifier]) {
                *stop = YES;
                return YES;
            }
            return NO;
        }];
        if (existing.count > 0) {
            [pending removeObjectsAtIndexes:existing];
        }
        [pending addObject:activation];
    }
}

static void DAMReleasePendingActivation(DAMSystemExtensionActivation *activation) {
    @synchronized(DAMPendingActivations()) {
        [DAMPendingActivations() removeObject:activation];
    }
}

static void DAMCopyMessage(NSString *message, char *buffer, size_t bufferLength) {
    if (buffer == NULL || bufferLength == 0) {
        return;
    }
    buffer[0] = '\0';
    const char *utf8 = message.UTF8String;
    if (utf8 == NULL) {
        return;
    }
    strlcpy(buffer, utf8, bufferLength);
}

@implementation DAMSystemExtensionActivation

- (instancetype)initWithBundleIdentifier:(NSString *)bundleIdentifier {
    self = [super init];
    if (self) {
        _bundleIdentifier = [bundleIdentifier copy];
        _semaphore = dispatch_semaphore_create(0);
        _status = DAMActivationStatusWaiting;
        _message = @"";
    }
    return self;
}

- (OSSystemExtensionReplacementAction)request:(OSSystemExtensionRequest *)request
                actionForReplacingExtension:(OSSystemExtensionProperties *)existing
                               withExtension:(OSSystemExtensionProperties *)ext {
    (void)request;
    (void)existing;
    (void)ext;
    return OSSystemExtensionReplacementActionReplace;
}

- (void)requestNeedsUserApproval:(OSSystemExtensionRequest *)request {
    (void)request;
    self.status = DAMActivationStatusNeedsApproval;
    self.message = @"approve DAM Network Protection in System Settings, then click Connect/Resume again";
    DAMRetainPendingActivation(self);
    [self complete];
}

- (void)request:(OSSystemExtensionRequest *)request didFinishWithResult:(OSSystemExtensionRequestResult)result {
    (void)request;
    DAMReleasePendingActivation(self);
    if (result == OSSystemExtensionRequestWillCompleteAfterReboot) {
        self.status = DAMActivationStatusNeedsReboot;
        self.message = @"DAM Network Protection will finish activating after reboot";
    } else {
        self.status = DAMActivationStatusReady;
        self.message = @"DAM Network Protection is active";
    }
    [self complete];
}

- (void)request:(OSSystemExtensionRequest *)request didFailWithError:(NSError *)error {
    (void)request;
    DAMReleasePendingActivation(self);
    self.status = DAMActivationStatusFailed;
    self.message = error.localizedDescription ?: @"DAM Network Protection activation failed";
    [self complete];
}

- (void)complete {
    if (self.completed) {
        return;
    }
    self.completed = YES;
    dispatch_semaphore_signal(self.semaphore);
}

@end

int dam_tray_activate_system_extension(const char *bundleIdentifier,
                                       double timeoutSeconds,
                                       char *messageBuffer,
                                       size_t messageBufferLength) {
    @autoreleasepool {
        if (bundleIdentifier == NULL || bundleIdentifier[0] == '\0') {
            DAMCopyMessage(@"missing System Extension bundle identifier", messageBuffer, messageBufferLength);
            return DAMActivationReturnInvalidArgument;
        }

        NSString *identifier = [NSString stringWithUTF8String:bundleIdentifier];
        if (identifier.length == 0) {
            DAMCopyMessage(@"invalid System Extension bundle identifier", messageBuffer, messageBufferLength);
            return DAMActivationReturnInvalidArgument;
        }

        DAMSystemExtensionActivation *pending = DAMPendingActivationForBundleIdentifier(identifier);
        if (pending != nil) {
            DAMCopyMessage(pending.message, messageBuffer, messageBufferLength);
            return DAMActivationReturnNeedsApproval;
        }

        DAMSystemExtensionActivation *activation = [[DAMSystemExtensionActivation alloc] initWithBundleIdentifier:identifier];
        OSSystemExtensionRequest *request = [OSSystemExtensionRequest activationRequestForExtension:identifier
                                                                                              queue:dispatch_get_main_queue()];
        request.delegate = activation;
        activation.request = request;

        void (^submitRequest)(void) = ^{
            [[OSSystemExtensionManager sharedManager] submitRequest:request];
        };
        if ([NSThread isMainThread]) {
            submitRequest();
        } else {
            dispatch_async(dispatch_get_main_queue(), submitRequest);
        }

        NSTimeInterval timeout = timeoutSeconds > 0 ? timeoutSeconds : 20.0;
        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:timeout];
        while (dispatch_semaphore_wait(activation.semaphore, dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC)) != 0) {
            if ([NSDate date].timeIntervalSinceReferenceDate >= deadline.timeIntervalSinceReferenceDate) {
                DAMCopyMessage(@"macOS did not register the DAM Network Protection activation request", messageBuffer, messageBufferLength);
                return DAMActivationReturnTimedOut;
            }
            if ([NSThread isMainThread]) {
                [[NSRunLoop mainRunLoop] runMode:NSDefaultRunLoopMode
                                      beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
            }
        }

        DAMCopyMessage(activation.message, messageBuffer, messageBufferLength);
        switch (activation.status) {
            case DAMActivationStatusReady:
                return DAMActivationReturnReady;
            case DAMActivationStatusNeedsApproval:
                return DAMActivationReturnNeedsApproval;
            case DAMActivationStatusNeedsReboot:
                return DAMActivationReturnNeedsReboot;
            case DAMActivationStatusFailed:
                return DAMActivationReturnFailed;
            case DAMActivationStatusWaiting:
            default:
                DAMCopyMessage(@"DAM Network Protection activation ended without a result", messageBuffer, messageBufferLength);
                return DAMActivationReturnFailed;
        }
    }
}
