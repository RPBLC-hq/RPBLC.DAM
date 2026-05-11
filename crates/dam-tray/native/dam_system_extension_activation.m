#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>
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

static const int DAMLoginItemReturnRegistered = 0;
static const int DAMLoginItemReturnFailed = 1;
static const int DAMLoginItemReturnRequiresApproval = 2;
static const int DAMLoginItemReturnUnsupported = 3;

@interface DAMSystemExtensionActivation : NSObject <OSSystemExtensionRequestDelegate>
@property(nonatomic, copy) NSString *bundleIdentifier;
@property(nonatomic, strong) dispatch_semaphore_t semaphore;
@property(nonatomic, strong) OSSystemExtensionRequest *request;
@property(nonatomic, assign) DAMActivationStatus status;
@property(nonatomic, copy) NSString *message;
@property(nonatomic, assign) BOOL completed;
@property(nonatomic, assign) BOOL deactivation;
- (instancetype)initWithBundleIdentifier:(NSString *)bundleIdentifier deactivation:(BOOL)deactivation;
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

static NSString *DAMLoginItemStatusName(SMAppServiceStatus status API_AVAILABLE(macos(13.0))) {
    switch (status) {
        case SMAppServiceStatusNotRegistered:
            return @"not_registered";
        case SMAppServiceStatusEnabled:
            return @"enabled";
        case SMAppServiceStatusRequiresApproval:
            return @"requires_approval";
        case SMAppServiceStatusNotFound:
            return @"not_found";
        default:
            return @"unknown";
    }
}

int dam_tray_register_login_item(char *messageBuffer, size_t messageBufferLength) {
    @autoreleasepool {
        if (@available(macOS 13.0, *)) {
            SMAppService *service = [SMAppService mainAppService];
            SMAppServiceStatus status = service.status;
            if (status == SMAppServiceStatusEnabled) {
                DAMCopyMessage(@"DAM is already registered to open at login", messageBuffer, messageBufferLength);
                return DAMLoginItemReturnRegistered;
            }

            NSError *error = nil;
            if (![service registerAndReturnError:&error]) {
                DAMCopyMessage(error.localizedDescription ?: @"failed to register DAM as a login item", messageBuffer, messageBufferLength);
                return DAMLoginItemReturnFailed;
            }

            status = service.status;
            if (status == SMAppServiceStatusEnabled) {
                DAMCopyMessage(@"DAM is registered to open at login", messageBuffer, messageBufferLength);
                return DAMLoginItemReturnRegistered;
            }
            if (status == SMAppServiceStatusRequiresApproval) {
                DAMCopyMessage(@"approve DAM in System Settings > General > Login Items, then continue setup", messageBuffer, messageBufferLength);
                return DAMLoginItemReturnRequiresApproval;
            }

            NSString *message = [NSString stringWithFormat:@"DAM login item registration ended with status %@", DAMLoginItemStatusName(status)];
            DAMCopyMessage(message, messageBuffer, messageBufferLength);
            return DAMLoginItemReturnFailed;
        }

        DAMCopyMessage(@"SMAppService login items require macOS 13 or newer", messageBuffer, messageBufferLength);
        return DAMLoginItemReturnUnsupported;
    }
}

int dam_tray_login_item_status(char *messageBuffer, size_t messageBufferLength) {
    @autoreleasepool {
        if (@available(macOS 13.0, *)) {
            SMAppServiceStatus status = [SMAppService mainAppService].status;
            DAMCopyMessage(DAMLoginItemStatusName(status), messageBuffer, messageBufferLength);
            if (status == SMAppServiceStatusEnabled) {
                return DAMLoginItemReturnRegistered;
            }
            if (status == SMAppServiceStatusRequiresApproval) {
                return DAMLoginItemReturnRequiresApproval;
            }
            return DAMLoginItemReturnFailed;
        }

        DAMCopyMessage(@"unsupported", messageBuffer, messageBufferLength);
        return DAMLoginItemReturnUnsupported;
    }
}

@implementation DAMSystemExtensionActivation

- (instancetype)initWithBundleIdentifier:(NSString *)bundleIdentifier deactivation:(BOOL)deactivation {
    self = [super init];
    if (self) {
        _bundleIdentifier = [bundleIdentifier copy];
        _semaphore = dispatch_semaphore_create(0);
        _status = DAMActivationStatusWaiting;
        _message = @"";
        _deactivation = deactivation;
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
    self.message = self.deactivation
        ? @"approve removing DAM Network Protection in System Settings"
        : @"approve DAM Network Protection in System Settings, then click Connect/Resume again";
    DAMRetainPendingActivation(self);
    [self complete];
}

- (void)request:(OSSystemExtensionRequest *)request didFinishWithResult:(OSSystemExtensionRequestResult)result {
    (void)request;
    DAMReleasePendingActivation(self);
    if (result == OSSystemExtensionRequestWillCompleteAfterReboot) {
        self.status = DAMActivationStatusNeedsReboot;
        self.message = self.deactivation
            ? @"DAM Network Protection will finish uninstalling after reboot"
            : @"DAM Network Protection will finish activating after reboot";
    } else {
        self.status = DAMActivationStatusReady;
        self.message = self.deactivation
            ? @"DAM Network Protection is deactivated"
            : @"DAM Network Protection is active";
    }
    [self complete];
}

- (void)request:(OSSystemExtensionRequest *)request didFailWithError:(NSError *)error {
    (void)request;
    DAMReleasePendingActivation(self);
    self.status = DAMActivationStatusFailed;
    self.message = error.localizedDescription ?: (self.deactivation
        ? @"DAM Network Protection deactivation failed"
        : @"DAM Network Protection activation failed");
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

        DAMSystemExtensionActivation *activation = [[DAMSystemExtensionActivation alloc] initWithBundleIdentifier:identifier deactivation:NO];
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

int dam_tray_deactivate_system_extension(const char *bundleIdentifier,
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

        DAMSystemExtensionActivation *deactivation = [[DAMSystemExtensionActivation alloc] initWithBundleIdentifier:identifier deactivation:YES];
        OSSystemExtensionRequest *request = [OSSystemExtensionRequest deactivationRequestForExtension:identifier
                                                                                                queue:dispatch_get_main_queue()];
        request.delegate = deactivation;
        deactivation.request = request;

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
        while (dispatch_semaphore_wait(deactivation.semaphore, dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC)) != 0) {
            if ([NSDate date].timeIntervalSinceReferenceDate >= deadline.timeIntervalSinceReferenceDate) {
                DAMCopyMessage(@"macOS did not register the DAM Network Protection deactivation request", messageBuffer, messageBufferLength);
                return DAMActivationReturnTimedOut;
            }
            if ([NSThread isMainThread]) {
                [[NSRunLoop mainRunLoop] runMode:NSDefaultRunLoopMode
                                      beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
            }
        }

        DAMCopyMessage(deactivation.message, messageBuffer, messageBufferLength);
        switch (deactivation.status) {
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
                DAMCopyMessage(@"DAM Network Protection deactivation ended without a result", messageBuffer, messageBufferLength);
                return DAMActivationReturnFailed;
        }
    }
}
