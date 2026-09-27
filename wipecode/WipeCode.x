// WipeCode.x — one dylib, two processes.
//
// The two roles cannot be merged into a single process, because FBSSystemService
// needs the com.apple.springboard entitlement and only SpringBoard carries it,
// while the pane has to live in Settings. So one dylib is injected into both
// processes and the bundle identifier decides which half runs. That keeps this a
// single tweak instead of two packages with a version dependency between them.
//
// The pane does not use a PreferenceBundles bundle. Two rounds of probing showed
// why that cannot work here: the pane specifier type PSWebView is hosted by
// PSWebViewController, and that class is not present in the Preferences process
// at all (the probe reports it NOT FOUND), so there is no class for Settings to
// instantiate. Settings also never enumerated the bundle. Rather than keep
// guessing at Apple's bundle rules, the tweak adds its own row to the Settings
// list and pushes its own controller with its own web view.
//
// Trust model: a Darwin notification carries no payload and any process may post
// one, so the notification is only a wake-up call. The actual authorisation is an
// HMAC-SHA256 over the typed password, keyed by a per-install random salt. The
// plaintext password never touches the disk or the wire.

#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import "../common/WipeCodeCommon.h"

// The page ships as a plain file next to the dylib rather than inside a
// PreferenceBundles bundle: that directory is enumerated by Settings, and a
// bundle there is expected to provide a controller class we do not have.
static NSString *const Vo1dekPaneHTMLPath = @"/var/jb/Library/WipeCode/pane.html";
static NSString *const Vo1dekPaneBundlesPath = @"/var/jb/Library/PreferenceBundles";
static NSString *const Vo1dekCellID = @"Vo1dekPaneCell";

static __weak WKWebView *Vo1dekPaneWebView;
static BOOL Vo1dekCountdownCancelled = NO;
static BOOL Vo1dekInjectedIntoList = NO;
static __weak UIViewController *Vo1dekRootList = nil;

#pragma mark - device passcode type

// Returns the first value these accessors yield. The spelling of the manager
// accessor and of the type property has moved around between iOS releases, so we
// probe a list rather than hard-coding one and record what actually answered.
static id Vo1dekFirstAvailable(id target, NSArray<NSString *> *names) {
    if (target == nil) return nil;
    for (NSString *name in names) {
        SEL sel = NSSelectorFromString(name);
        if (![target respondsToSelector:sel]) continue;
        @try {
            id value = [target valueForKey:name];
            if (value != nil && value != [NSNull null]) return value;
        } @catch (NSException *e) {
            // Wrong type or unavailable ivar: try the next candidate.
        }
    }
    return nil;
}

static id Vo1dekSharedInstanceOf(NSString *className, NSArray<NSString *> *accessors) {
    Class cls = NSClassFromString(className);
    if (cls == Nil) return nil;
    for (NSString *accessor in accessors) {
        SEL sel = NSSelectorFromString(accessor);
        if (![cls respondsToSelector:sel]) continue;
        @try {
            id instance = ((id (*)(id, SEL))objc_msgSend)((id)cls, sel);
            if (instance) return instance;
        } @catch (NSException *e) {
        }
    }
    return nil;
}

// Maps the raw passcode-type value onto what the Settings pane needs: a keyboard
// type plus a length constraint. The raw value is always reported alongside so a
// wrong mapping here is visible in the log rather than silently mistyping the pad.
static NSDictionary *Vo1dekDescribePasscodeType(NSNumber *raw) {
    if (raw == nil) {
        return @{@"type": @"unknown", @"numeric": @NO, @"min": @4, @"max": @0, @"raw": @(-1)};
    }
    NSInteger v = raw.integerValue;
    // Matches the shape of LSPasscodeType: none, alpha-numeric (4/6/general),
    // numeric (4/6/general), and the legacy numeric-only value.
    NSString *name = nil;
    BOOL numeric = NO;
    NSInteger minLen = 4, maxLen = 0;

    switch (v) {
        case 0: name = @"none"; break;
        case 1: name = @"alphanumeric"; break;
        case 2: name = @"alphanumeric4"; minLen = maxLen = 4; break;
        case 3: name = @"alphanumeric6"; minLen = maxLen = 6; break;
        case 4: name = @"numeric"; numeric = YES; break;
        case 5: name = @"numeric4"; numeric = YES; minLen = maxLen = 4; break;
        case 6: name = @"numeric6"; numeric = YES; minLen = maxLen = 6; break;
        case 7: name = @"numericLegacy"; numeric = YES; break;
        default: name = [NSString stringWithFormat:@"raw%ld", (long)v]; break;
    }

    return @{@"type": name, @"numeric": @(numeric), @"min": @(minLen), @"max": @(maxLen), @"raw": @(v)};
}

static NSDictionary *Vo1dekCurrentPasscodeType(void) {
    NSArray *managers = @[@"SBAuthenticationManager", @"SBLockScreenManager", @"SBDisplayDevice"];
    NSArray *accessors = @[@"sharedAuthenticationManager", @"sharedInstance", @"defaultManager", @"sharedManager", @"defaultInstance"];
    NSArray *typeKeys = @[@"passcodeType", @"_passcodeType", @"passcodeTypeValue", @"type"];

    for (NSString *name in managers) {
        id manager = Vo1dekSharedInstanceOf(name, accessors);
        if (manager == nil) continue;
        id value = Vo1dekFirstAvailable(manager, typeKeys);
        if (![value isKindOfClass:[NSNumber class]]) continue;
        Vo1dekLog(@"[passcode] %@ -> %@", name, value);
        return Vo1dekDescribePasscodeType((NSNumber *)value);
    }

    Vo1dekLog(@"[passcode] no manager answered; reporting unknown");
    return Vo1dekDescribePasscodeType(nil);
}

static void Vo1dekPublishDeviceInfo(void) {
    NSMutableDictionary *plist = [(Vo1dekReadPlist(VO1DEK_DEVICE) ?: @{}) mutableCopy];
    [plist addEntriesFromDictionary:Vo1dekCurrentPasscodeType()];
    Vo1dekWritePlist(plist, VO1DEK_DEVICE);
}

#pragma mark - erase request (SpringBoard role)

static void Vo1dekPublishResult(BOOL ok, NSString *method, NSString *error) {
    Vo1dekWritePlist(@{@"ok": @(ok), @"method": method ?: @"", @"error": error ?: @""}, VO1DEK_RESULT);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         (__bridge CFStringRef)VO1DEK_NOTIFY_RESULT,
                                         NULL, NULL, YES);
}

// Primary path, and the only one the device probe supports.
//
// The probe on iOS 16 found no SBDeviceErase at all, but it did find both halves
// of a real call: FBSSystemService -dataResetWithRequest:completion:, and
// FBSDataResetRequest as the argument class. The probe also produced its only
// initialiser, so the request carries all three keys instead of relying on -new.
static BOOL Vo1dekEraseViaSystemService(NSString **outError) {
    Class serviceCls = NSClassFromString(@"FBSSystemService");
    if (serviceCls == Nil) {
        *outError = @"FBSSystemService not present";
        return NO;
    }
    Class requestCls = NSClassFromString(@"FBSDataResetRequest");
    if (requestCls == Nil) {
        *outError = @"FBSDataResetRequest not present";
        return NO;
    }

    SEL serviceSel = NSSelectorFromString(@"sharedService");
    if (![serviceCls respondsToSelector:serviceSel]) {
        *outError = @"+sharedService not present";
        return NO;
    }
    id service = ((id (*)(id, SEL))objc_msgSend)((id)serviceCls, serviceSel);
    if (service == nil) {
        *outError = @"+sharedService returned nil";
        return NO;
    }

    SEL initSel = NSSelectorFromString(@"initWithMode:options:reason:");
    if (![requestCls instancesRespondToSelector:initSel]) {
        *outError = @"initWithMode:options:reason: not present";
        return NO;
    }
    SEL performSel = NSSelectorFromString(@"dataResetWithRequest:completion:");
    if (![service respondsToSelector:performSel]) {
        *outError = @"dataResetWithRequest:completion: not present";
        return NO;
    }

    // The probe gave the designated initialiser as
    //   - initWithMode:options:reason:  @40@0:8q16q24@32
    // so mode and options are both long long and reason is an NSString. What the
    // individual values mean is not visible in a method list, so zero is used for
    // both, which is the default "no extra flags" case, and the reason carries the
    // provenance. If the service rejects it, the completion block reports why and
    // the enum values can be read off a real Settings reset from a disassembly.
    const long long mode = 0;
    const long long options = 0;
    NSString *reason = @"WipeCode authenticated request";

    // objc_msgSend is declared to return void, so the call has to go through a
    // void * and be read back as the id the initialiser actually returns.
    void *raw = ((void *(*)(id, SEL, long long, long long, id))objc_msgSend)(
        (id)requestCls, initSel, mode, options, reason);
    id request = (__bridge_transfer id)raw;
    if (request == nil) {
        *outError = @"initWithMode:options:reason: returned nil";
        return NO;
    }

    // Read the values back so the log shows what the class actually stored rather
    // than what we passed in.
    SEL optionsSel = NSSelectorFromString(@"options");
    SEL modeSel = NSSelectorFromString(@"mode");
    SEL reasonSel = NSSelectorFromString(@"reason");
    Vo1dekLog(@"[erase] request built: mode=%lld options=%lld reason=%@",
              [request respondsToSelector:modeSel]
                  ? ((long long (*)(id, SEL))objc_msgSend)(request, modeSel) : -1,
              [request respondsToSelector:optionsSel]
                  ? ((long long (*)(id, SEL))objc_msgSend)(request, optionsSel) : -1,
              [request respondsToSelector:reasonSel]
                  ? ((id (*)(id, SEL))objc_msgSend)(request, reasonSel) : @"(unreadable)");

    Vo1dekLog(@"[erase] dispatching dataResetWithRequest: request=%@", request);
    void (*perform)(id, SEL, id, id) = (void (*)(id, SEL, id, id))objc_msgSend;
    perform(service, performSel, request, ^(BOOL success, NSError *error) {
        Vo1dekLog(@"[erase] dataReset completion success=%d error=%@", (int)success, error);
        Vo1dekPublishResult(success, @"dataResetWithRequest", error.localizedDescription ?: @"");
    });
    return YES;
}

// Fallback for builds where the system service path does not answer. It needs
// passwordless sudo, which the user sets up once by creating
// /var/jb/etc/sudoers.d/vo1dek containing:
//   mobile ALL=(root) NOPASSWD: /usr/bin/fdesetup
// The argument vector itself is read from secret.plist under "rootEraseArgs" so
// it can be corrected against the real `fdesetup -h` output in the probe log.
static BOOL Vo1dekEraseViaRoot(NSString **outError) {
    NSString *sudoers = @"/var/jb/etc/sudoers.d/vo1dek";
    if (![[NSFileManager defaultManager] fileExistsAtPath:sudoers]) {
        *outError = @"no /var/jb/etc/sudoers.d/vo1dek, root path disabled";
        return NO;
    }

    NSDictionary *secret = Vo1dekReadPlist(VO1DEK_SECRET);
    NSArray *args = secret[@"rootEraseArgs"];
    if (![args isKindOfClass:[NSArray class]] || args.count == 0) {
        *outError = @"rootEraseArgs missing from secret.plist";
        return NO;
    }

    NSString *label = [NSString stringWithFormat:@"fdesetup %@", [args componentsJoinedByString:@" "]];
    int status = -1;
    NSString *text = Vo1dekRunProcess(@"/var/jb/usr/bin/sudo",
                                      [@[@"-n", @"/usr/bin/fdesetup"] arrayByAddingObjectsFromArray:args],
                                      &status);
    if (text == nil) {
        *outError = @"could not run sudo";
        return NO;
    }
    Vo1dekLog(@"[erase] %@ status=%d out=%@", label, status, text);
    BOOL ok = (status == 0);
    Vo1dekPublishResult(ok, label, text);
    if (!ok && *outError == nil) *outError = text;
    return ok;
}

static void Vo1dekPerformErase(void) {
    NSString *error = nil;
    if (Vo1dekEraseViaSystemService(&error)) return;
    Vo1dekLog(@"[erase] dataReset path unavailable: %@", error);

    Vo1dekLog(@"[erase] system service path exhausted, falling back to root");
    if (Vo1dekEraseViaRoot(&error)) return;

    Vo1dekLog(@"[erase] all paths failed: %@", error);
    Vo1dekPublishResult(NO, @"none", error ?: @"no working erase path");
}

#pragma mark - request handling (SpringBoard role)

static void Vo1dekHandleRequest(void) {
    NSDictionary *request = Vo1dekReadPlist(VO1DEK_REQUEST);
    if (request == nil) {
        Vo1dekLog(@"[request] no request file, ignoring");
        return;
    }

    // Consume it first: a request must never be replayable.
    [[NSFileManager defaultManager] removeItemAtPath:VO1DEK_REQUEST error:NULL];

    NSString *candidate = request[@"digest"];
    NSDictionary *secret = Vo1dekReadPlist(VO1DEK_SECRET);
    NSString *salt = secret[@"salt"];
    NSString *expected = secret[@"digest"];

    if (![candidate isKindOfClass:[NSString class]] || candidate.length == 0) {
        Vo1dekLog(@"[request] malformed digest, refusing");
        Vo1dekPublishResult(NO, @"auth", @"malformed request");
        return;
    }
    if (![salt isKindOfClass:[NSString class]] || ![expected isKindOfClass:[NSString class]]) {
        Vo1dekLog(@"[request] no wipe password configured, refusing");
        Vo1dekPublishResult(NO, @"auth", @"no wipe password configured");
        return;
    }
    if (!Vo1dekSecretEquals(candidate, expected)) {
        Vo1dekLog(@"[request] digest mismatch, refusing");
        Vo1dekPublishResult(NO, @"auth", @"wrong password");
        return;
    }

    Vo1dekLog(@"[request] authorised, erasing");
    Vo1dekPerformErase();
}

#pragma mark - request notification plumbing (SpringBoard role)

static const void *Vo1dekToken;

static void Vo1dekDarwinCallback(CFNotificationCenterRef center, void *observer,
                                 CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    // Delivered on an arbitrary thread.
    dispatch_async(dispatch_get_main_queue(), ^{
        Vo1dekHandleRequest();
    });
}

static void Vo1dekStartSpringBoard(void) {
    Vo1dekLog(@"[boot] SpringBoard role active");

    // Reading private SpringBoard state from inside the constructor runs while
    // SpringBoard is still initialising, which is a good way to take it down.
    // Let the boot sequence finish first.
    dispatch_async(dispatch_get_main_queue(), ^{
        Vo1dekPublishDeviceInfo();
    });

    // Registered synchronously so a request that arrives during startup is not lost.
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                    Vo1dekToken,
                                    Vo1dekDarwinCallback,
                                    (__bridge CFStringRef)VO1DEK_NOTIFY_REQUEST,
                                    NULL,
                                    CFNotificationSuspensionBehaviorCoalesce);

    // A request written just before we started observing would otherwise be missed.
    if (Vo1dekReadPlist(VO1DEK_REQUEST) != nil) {
        Vo1dekHandleRequest();
    }
}

#pragma mark - settings helpers

static UIViewController *Vo1dekTopViewController(void) {
    UIWindow *key = nil;
    for (UIWindow *window in [UIApplication sharedApplication].windows) {
        if (window.isKeyWindow) {
            key = window;
            break;
        }
    }
    if (key == nil) {
        for (UIWindow *window in [UIApplication sharedApplication].windows) {
            if (!window.isHidden) {
                key = window;
                break;
            }
        }
    }
    UIViewController *vc = key.rootViewController;
    while (vc.presentedViewController != nil) {
        vc = vc.presentedViewController;
    }
    return vc;
}

static void Vo1dekPushToPane(NSString *js) {
    WKWebView *pane = Vo1dekPaneWebView;
    if (pane == nil) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        [pane evaluateJavaScript:js completionHandler:nil];
    });
}

static NSDictionary *Vo1dekDeviceInfo(void) {
    return Vo1dekReadPlist(VO1DEK_DEVICE) ?: @{};
}

static NSDictionary *Vo1dekSecret(void) {
    return Vo1dekReadPlist(VO1DEK_SECRET) ?: @{};
}

// Escapes a string for embedding in a JS string literal.
static NSString *Vo1dekJsString(NSString *value) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:@[value ?: @""] options:0 error:NULL];
    NSString *json = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"\"\"";
    return [json substringWithRange:NSMakeRange(1, json.length - 2)];
}

static void Vo1dekSendStatus(void) {
    NSDictionary *device = Vo1dekDeviceInfo();
    NSDictionary *secret = Vo1dekSecret();
    NSDictionary *result = Vo1dekReadPlist(VO1DEK_RESULT) ?: @{};

    NSInteger minLen = 4;
    if ([device[@"min"] isKindOfClass:[NSNumber class]]) minLen = [device[@"min"] integerValue];
    NSInteger maxLen = 0;
    if ([device[@"max"] isKindOfClass:[NSNumber class]]) maxLen = [device[@"max"] integerValue];

    NSString *js = [NSString stringWithFormat:
        @"window.vo1dekStatus && window.vo1dekStatus({configured:%@, passcodeType:%@, numeric:%@, min:%d, max:%d, ok:%@, method:%@, error:%@});",
        [secret[@"digest"] isKindOfClass:[NSString class]] ? @"true" : @"false",
        Vo1dekJsString(device[@"type"] ?: @"unknown"),
        [device[@"numeric"] boolValue] ? @"true" : @"false",
        (int)minLen, (int)maxLen,
        [result[@"ok"] boolValue] ? @"true" : @"false",
        Vo1dekJsString(result[@"method"] ?: @""),
        Vo1dekJsString(result[@"error"] ?: @"")];

    Vo1dekLog(@"[pref] status configured=%@ type=%@", secret[@"digest"] != nil, device[@"type"]);
    Vo1dekPushToPane(js);
}

// Adds one secure field whose keyboard follows the passcode type the SpringBoard
// role published for this device.
static void Vo1dekAddPasswordField(UIAlertController *alert, NSString *placeholder) {
    BOOL numeric = [Vo1dekDeviceInfo()[@"numeric"] boolValue];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.placeholder = placeholder;
        tf.secureTextEntry = YES;
        tf.autocorrectionType = UITextAutocorrectionTypeNo;
        tf.autocapitalizationType = UITextAutocapitalizationTypeNone;
        tf.spellCheckingType = UITextSpellCheckingTypeNo;
        tf.textContentType = nil;
        tf.keyboardType = numeric ? UIKeyboardTypeNumberPad : UIKeyboardTypeASCIICapable;
    }];
}

static void Vo1dekShowNotice(NSString *title, NSString *message) {
    UIAlertController *notice = [UIAlertController alertControllerWithTitle:title
                                                                    message:message
                                                             preferredStyle:UIAlertControllerStyleAlert];
    [notice addAction:[UIAlertAction actionWithTitle:@"ОК" style:UIAlertActionStyleDefault handler:nil]];
    UIViewController *presenter = Vo1dekTopViewController();
    if (presenter == nil) return;
    [presenter presentViewController:notice animated:YES completion:nil];
}

#pragma mark - password storage

static void Vo1dekStorePassword(NSString *password) {
    NSString *salt = Vo1dekRandomHex(32);
    NSString *digest = Vo1dekHMAC(salt, password);
    Vo1dekWritePlist(@{@"salt": salt, @"digest": digest}, VO1DEK_SECRET);
    Vo1dekLog(@"[pref] wipe password stored");
    Vo1dekSendStatus();
}

static void Vo1dekClearPassword(void) {
    [[NSFileManager defaultManager] removeItemAtPath:VO1DEK_SECRET error:NULL];
    Vo1dekLog(@"[pref] wipe password cleared");
    Vo1dekSendStatus();
}

#pragma mark - erase prompt

// Nothing is dispatched until the count reaches zero, and each step dismisses the
// previous alert first — UIKit refuses to present on top of a presented controller.
//
// The cancel flag is honoured here, at the top of each step, because that is where
// the recursive call re-enters. Starting a fresh countdown clears it first, so a
// flag left set by a step whose dismissal callback never fired cannot abort the
// next attempt.
static void Vo1dekCountdownStep(NSString *password, NSInteger remaining) {
    if (Vo1dekCountdownCancelled) {
        Vo1dekCountdownCancelled = NO;
        Vo1dekLog(@"[pref] countdown cancelled");
        Vo1dekSendStatus();
        return;
    }

    if (remaining <= 0) {
        NSString *salt = Vo1dekSecret()[@"salt"];
        if (![salt isKindOfClass:[NSString class]]) {
            Vo1dekLog(@"[pref] cannot arm: no salt");
            Vo1dekShowNotice(@"Ошибка", @"Пароль стирания не настроен.");
            return;
        }
        Vo1dekWritePlist(@{@"digest": Vo1dekHMAC(salt, password)}, VO1DEK_REQUEST);
        Vo1dekLog(@"[pref] request written, notifying SpringBoard");
        CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                             (__bridge CFStringRef)VO1DEK_NOTIFY_REQUEST,
                                             NULL, NULL, YES);
        return;
    }

    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:[NSString stringWithFormat:@"Стерть через %ld", (long)remaining]
                         message:@"Будут удалены все данные и настройки."
                  preferredStyle:UIAlertControllerStyleAlert];

    [alert addAction:[UIAlertAction actionWithTitle:@"Отмена" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
        Vo1dekCountdownCancelled = YES;
    }]];

    UIViewController *presenter = Vo1dekTopViewController();
    if (presenter == nil) return;
    [presenter presentViewController:alert animated:NO completion:^{
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [alert dismissViewControllerAnimated:NO completion:^{
                Vo1dekCountdownStep(password, remaining - 1);
            }];
        });
    }];
}

static void Vo1dekPromptAndMaybeWipe(void) {
    NSDictionary *device = Vo1dekDeviceInfo();
    if (![Vo1dekSecret()[@"digest"] isKindOfClass:[NSString class]]) {
        Vo1dekLog(@"[pref] wipe requested with no password configured");
        Vo1dekShowNotice(@"Не настроено", @"Сначала задайте пароль стирания.");
        return;
    }

    NSString *type = device[@"type"] ?: @"unknown";
    NSInteger minLen = 4, maxLen = 0;
    if ([device[@"min"] isKindOfClass:[NSNumber class]]) minLen = [device[@"min"] integerValue];
    if ([device[@"max"] isKindOfClass:[NSNumber class]]) maxLen = [device[@"max"] integerValue];

    NSString *hint = maxLen > 0
        ? [NSString stringWithFormat:@"Формат устройства: ровно %ld символов.", (long)maxLen]
        : [NSString stringWithFormat:@"Формат устройства: %@, от %ld символов.", type, (long)minLen];

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Стереть устройство"
                                                                    message:hint
                                                             preferredStyle:UIAlertControllerStyleAlert];
    Vo1dekAddPasswordField(alert, @"Пароль стирания");
    [alert addAction:[UIAlertAction actionWithTitle:@"Отмена" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Продолжить" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        NSString *password = alert.textFields.firstObject.text ?: @"";
        // A tapped action dismisses the alert, and UIKit will not present another
        // controller on top of one that is still on screen. Hand the follow-up to
        // the next main-queue turn so the dismissal has committed first.
        dispatch_async(dispatch_get_main_queue(), ^{
            if (password.length < (NSUInteger)minLen || (maxLen > 0 && password.length != (NSUInteger)maxLen)) {
                Vo1dekLog(@"[pref] length check failed: got %lu, want %ld..%ld",
                          (unsigned long)password.length, (long)minLen, (long)maxLen);
                Vo1dekShowNotice(@"Неверная длина", @"Пароль не соответствует формату код-пароль этого устройства.");
                return;
            }
            Vo1dekCountdownCancelled = NO;
            Vo1dekCountdownStep(password, 5);
        });
    }]];

    UIViewController *presenter = Vo1dekTopViewController();
    if (presenter == nil) return;
    [presenter presentViewController:alert animated:YES completion:nil];
}

#pragma mark - password setup

static void Vo1dekPromptForNewPassword(BOOL confirming, NSString *firstEntry) {
    NSDictionary *device = Vo1dekDeviceInfo();
    NSString *type = device[@"type"] ?: @"unknown";
    NSInteger minLen = 4;
    if ([device[@"min"] isKindOfClass:[NSNumber class]]) minLen = [device[@"min"] integerValue];

    NSString *title = confirming ? @"Повторите пароль" : @"Новый пароль стирания";
    NSString *hint = confirming
        ? @"Введите его ещё раз, чтобы подтвердить."
        : [NSString stringWithFormat:@"Не менее %ld символов. Формат устройства: %@.", (long)minLen, type];

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                    message:hint
                                                             preferredStyle:UIAlertControllerStyleAlert];
    Vo1dekAddPasswordField(alert, @"Пароль");
    [alert addAction:[UIAlertAction actionWithTitle:@"Отмена" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:confirming ? @"Сохранить" : @"Далее"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        NSString *password = alert.textFields.firstObject.text ?: @"";
        // See the note in Vo1dekPromptAndMaybeWipe: the follow-up runs on the
        // next main-queue turn so this alert has finished dismissing.
        dispatch_async(dispatch_get_main_queue(), ^{
            if (password.length < (NSUInteger)minLen) {
                Vo1dekShowNotice(@"Слишком короткий", @"Пароль короче минимальной длины для этого устройства.");
                return;
            }
            if (!confirming) {
                Vo1dekPromptForNewPassword(YES, password);
            } else if (![firstEntry isEqualToString:password]) {
                Vo1dekLog(@"[pref] confirmation mismatch");
                Vo1dekShowNotice(@"Не совпадает", @"Пароли различаются.");
            } else {
                Vo1dekStorePassword(password);
            }
        });
    }]];

    UIViewController *presenter = Vo1dekTopViewController();
    if (presenter == nil) return;
    [presenter presentViewController:alert animated:YES completion:nil];
}

#pragma mark - web view bridge

@interface Vo1dekBridge : NSObject <WKScriptMessageHandler>
@end

@implementation Vo1dekBridge

+ (instancetype)shared {
    static Vo1dekBridge *shared;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ shared = [Vo1dekBridge new]; });
    return shared;
}

- (void)userContentController:(WKUserContentController *)controller
      didReceiveScriptMessage:(WKScriptMessage *)message {
    if (![message.name isEqualToString:@"vo1dek"]) return;

    // The web view is created by this tweak and nothing else can reach the
    // handler, but the identity check costs nothing and keeps any other Settings
    // web view from driving an erase.
    WKWebView *pane = Vo1dekPaneWebView;
    if (pane == nil || message.webView != pane) {
        Vo1dekLog(@"[pref] rejected message from unexpected pane: %@", message.webView.URL);
        return;
    }

    NSDictionary *body = [message.body isKindOfClass:[NSDictionary class]] ? message.body : @{};
    NSString *action = body[@"action"];
    Vo1dekLog(@"[pref] action=%@", action);

    if ([action isEqualToString:@"status"]) {
        Vo1dekSendStatus();
    } else if ([action isEqualToString:@"setPassword"]) {
        Vo1dekPromptForNewPassword(NO, nil);
    } else if ([action isEqualToString:@"clear"]) {
        Vo1dekClearPassword();
    } else if ([action isEqualToString:@"wipe"]) {
        Vo1dekPromptAndMaybeWipe();
    }
}

@end

#pragma mark - our own pane

// Settings has no usable host class for a web pane on this iOS, so the pane is a
// plain controller pushed by the tweak itself. The page is the same HTML as
// before; only the container changed.
@interface WipeCodePaneViewController : UIViewController <WKNavigationDelegate>
@end

@implementation WipeCodePaneViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"WipeCode";
    // The page paints its own black background, so the controller must not flash
    // a lighter one while the web view is being set up.
    self.view.backgroundColor = [UIColor blackColor];

    WKWebViewConfiguration *config = [WKWebViewConfiguration new];
    [config.userContentController addScriptMessageHandler:Vo1dekBridge.shared name:@"vo1dek"];

    WKWebView *web = [[WKWebView alloc] initWithFrame:self.view.bounds configuration:config];
    web.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    web.navigationDelegate = self;
    [self.view addSubview:web];
    Vo1dekPaneWebView = web;

    NSString *html = [NSString stringWithContentsOfFile:Vo1dekPaneHTMLPath
                                                encoding:NSUTF8StringEncoding
                                                   error:NULL];
    if (html.length == 0) {
        Vo1dekLog(@"[pref] pane html missing at %@", Vo1dekPaneHTMLPath);
        UILabel *missing = [[UILabel alloc] initWithFrame:self.view.bounds];
        missing.numberOfLines = 0;
        missing.textAlignment = NSTextAlignmentCenter;
        missing.textColor = [UIColor whiteColor];
        missing.text = [NSString stringWithFormat:@"pane.html не найден\n%@", Vo1dekPaneHTMLPath];
        missing.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        [self.view addSubview:missing];
        return;
    }

    [web loadHTMLString:html baseURL:[NSURL fileURLWithPath:Vo1dekPaneHTMLPath]];
}

- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation {
    Vo1dekSendStatus();
}

@end

#pragma mark - adding a row to the Settings list

// The row is appended to the last section of the list, and its index is derived
// from the count Settings itself reports, so a real row is never displaced and no
// hard-coded section number is involved.

typedef NSInteger (*Vo1dekRowsIMP)(id, SEL, UITableView *, NSInteger);
typedef UITableViewCell *(*Vo1dekCellIMP)(id, SEL, UITableView *, NSIndexPath *);
typedef void (*Vo1dekSelectIMP)(id, SEL, UITableView *, NSIndexPath *);

static Vo1dekRowsIMP Vo1dekOrigRows;
static Vo1dekCellIMP Vo1dekOrigCell;
static Vo1dekSelectIMP Vo1dekOrigSelect;

// The list asks for its own row and section counts while it lays out, so asking
// the table view anything from inside these hooks can re-enter them. While the
// guard is up the hooks stay out of the way and let Settings' code run.
static BOOL Vo1dekInHook = NO;

static NSInteger Vo1dekLastSection(UITableView *tv) {
    NSInteger sections = (NSInteger)[tv numberOfSections];
    return sections > 0 ? sections - 1 : 0;
}

// YES when the index path addresses our own row rather than one of Settings'.
// The host is compared against the one list instance we patched, so the row can
// never leak onto any other Settings page that happens to share the class.
static BOOL Vo1dekIsOurRow(id host, SEL rowsSel, UITableView *tv, NSIndexPath *path) {
    if (Vo1dekOrigRows == NULL) return NO;
    if (host != Vo1dekRootList) return NO;
    if (path.section != Vo1dekLastSection(tv)) return NO;
    NSInteger theirs = Vo1dekOrigRows(host, rowsSel, tv, path.section);
    return path.row == theirs;
}

static NSInteger Vo1dekRowsHook(id self, SEL _cmd, UITableView *tv, NSInteger section) {
    if (Vo1dekInHook) return Vo1dekOrigRows(self, _cmd, tv, section);
    Vo1dekInHook = YES;
    NSInteger n = Vo1dekOrigRows(self, _cmd, tv, section);
    if (self == Vo1dekRootList && section == Vo1dekLastSection(tv)) n += 1;
    Vo1dekInHook = NO;
    return n;
}

// Settings draws its own icons as small rounded tiles, so ours is drawn the same
// way instead of shipping a loose image. The power glyph is stroked by hand: the
// deployment target predates SF Symbols and the build treats unguarded
// availability as an error, so no iOS 13 only API may be referenced here.
static UIImage *Vo1dekPaneIcon(void) {
    static UIImage *icon = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        UIGraphicsImageRenderer *renderer =
            [[UIGraphicsImageRenderer alloc] initWithSize:CGSizeMake(29.0, 29.0)];
        icon = [renderer imageWithActions:^(UIGraphicsImageRendererContext *context) {
            CGRect rect = CGRectMake(0.0, 0.0, 29.0, 29.0);
            CGContextRef ctx = context.CGContext;
            UIBezierPath *tile = [UIBezierPath bezierPathWithRoundedRect:rect cornerRadius:7.0];

            [[UIColor colorWithRed:0.62 green:0.09 blue:0.11 alpha:1.0] setFill];
            [tile fill];

            CGContextSaveGState(ctx);
            CGContextAddPath(ctx, tile.CGPath);
            CGContextClip(ctx);
            CGColorSpaceRef space = CGColorSpaceCreateDeviceRGB();
            CGFloat components[8] = {
                0.93, 0.24, 0.24, 1.0,
                0.74, 0.11, 0.14, 1.0
            };
            CGFloat locations[2] = {0.0, 1.0};
            CGGradientRef gradient = CGGradientCreateWithColorComponents(space, components, locations, 2);
            if (gradient != NULL) {
                CGContextDrawLinearGradient(ctx, gradient,
                                            CGPointMake(0.0, 0.0),
                                            CGPointMake(29.0, 29.0),
                                            (CGGradientDrawingOptions)0);
                CGGradientRelease(gradient);
            }
            CGColorSpaceRelease(space);
            CGContextRestoreGState(ctx);

            CGFloat centreX = 14.5;
            CGFloat centreY = 15.5;
            CGFloat radius = 6.2;
            CGContextSetStrokeColorWithColor(ctx, [[UIColor whiteColor] CGColor]);
            CGContextSetLineWidth(ctx, 2.0);
            CGContextSetLineCap(ctx, kCGLineCapRound);
            CGContextAddArc(ctx, centreX, centreY, radius,
                            (CGFloat)(-M_PI_4), (CGFloat)(M_PI * 1.25), 0);
            CGContextStrokePath(ctx);
            CGContextMoveToPoint(ctx, centreX, centreY - radius - 3.4);
            CGContextAddLineToPoint(ctx, centreX, centreY);
            CGContextStrokePath(ctx);
        }];
    });
    return icon;
}

static UITableViewCell *Vo1dekPaneCell(UITableView *tv) {
    UITableViewCell *cell = [tv dequeueReusableCellWithIdentifier:Vo1dekCellID];
    if (cell == nil) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                                      reuseIdentifier:Vo1dekCellID];
    }
    cell.textLabel.text = @"WipeCode";
    UIImage *icon = Vo1dekPaneIcon();
    if (icon != nil) {
        cell.imageView.image = icon;
        cell.imageView.layer.masksToBounds = YES;
    }
    NSDictionary *device = Vo1dekDeviceInfo();
    BOOL configured = [Vo1dekSecret()[@"digest"] isKindOfClass:[NSString class]];
    cell.detailTextLabel.text = configured
        ? [NSString stringWithFormat:@"Пароль стирания задан · %@", device[@"type"] ?: @"unknown"]
        : @"Пароль стирания не задан";
    cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    return cell;
}

static UITableViewCell *Vo1dekCellHook(id self, SEL _cmd, UITableView *tv, NSIndexPath *path) {
    SEL rowsSel = @selector(tableView:numberOfRowsInSection:);
    if (!Vo1dekInHook && Vo1dekIsOurRow(self, rowsSel, tv, path)) {
        Vo1dekInHook = YES;
        UITableViewCell *cell = Vo1dekPaneCell(tv);
        Vo1dekInHook = NO;
        return cell;
    }
    return Vo1dekOrigCell(self, _cmd, tv, path);
}

// Settings does not use a UINavigationController: PSUIPrefsRootController is its
// own container and exposes pushViewController:animated:. So walk up the parent
// chain until something can push, instead of assuming a navigation controller.
static void Vo1dekPushPane(id host) {
    WipeCodePaneViewController *pane = [WipeCodePaneViewController new];

    UIViewController *node = (UIViewController *)host;
    NSUInteger guard = 0;
    while (node != nil && guard < 32) {
        if ([node respondsToSelector:@selector(pushViewController:animated:)]) {
            [node performSelector:@selector(pushViewController:animated:)
                        withObject:pane
                        withObject:@(YES)];
            Vo1dekLog(@"[pane] pushed own controller into %@", NSStringFromClass([node class]));
            return;
        }
        if ([node respondsToSelector:@selector(presentViewController:animated:completion:)]) {
            UINavigationController *wrapper =
                [[UINavigationController alloc] initWithRootViewController:pane];
            [node presentViewController:wrapper animated:YES completion:nil];
            Vo1dekLog(@"[pane] presented own controller above %@", NSStringFromClass([node class]));
            return;
        }
        node = node.parentViewController;
        guard++;
    }
    Vo1dekLog(@"[pane] no container could present the pane");
}

static void Vo1dekSelectHook(id self, SEL _cmd, UITableView *tv, NSIndexPath *path) {
    SEL rowsSel = @selector(tableView:numberOfRowsInSection:);
    if (!Vo1dekInHook && Vo1dekIsOurRow(self, rowsSel, tv, path)) {
        Vo1dekInHook = YES;
        [tv deselectRowAtIndexPath:path animated:YES];
        Vo1dekInHook = NO;
        Vo1dekPushPane(self);
        return;
    }
    Vo1dekOrigSelect(self, _cmd, tv, path);
}

// Settings does not contain its lists the usual way. PSUIPrefsRootController
// keeps them in an array it manages itself through -setViewControllers:animated:,
// so -childViewControllers stays empty and every walk of the containment graph
// dead ends at a bare UINavigationController. The container is therefore hooked
// directly and asked for the list it draws the top level screen with.
static void Vo1dekInstallRow(UIViewController *list) {
    if (list == nil) return;
    if (![list respondsToSelector:@selector(tableView)]) {
        Vo1dekLog(@"[pane] %@ has no table", NSStringFromClass([list class]));
        return;
    }

    Class cls = [list class];
    NSString *name = NSStringFromClass(cls);
    SEL rowsSel = @selector(tableView:numberOfRowsInSection:);
    SEL cellSel = @selector(tableView:cellForRowAtIndexPath:);
    SEL selectSel = @selector(tableView:didSelectRowAtIndexPath:);

    Method rowsM = class_getInstanceMethod(cls, rowsSel);
    Method cellM = class_getInstanceMethod(cls, cellSel);
    Method selectM = class_getInstanceMethod(cls, selectSel);
    if (rowsM == NULL || cellM == NULL || selectM == NULL) {
        Vo1dekLog(@"[pane] %@ does not implement the table callbacks", name);
        return;
    }

    Vo1dekOrigRows = (Vo1dekRowsIMP)method_getImplementation(rowsM);
    Vo1dekOrigCell = (Vo1dekCellIMP)method_getImplementation(cellM);
    Vo1dekOrigSelect = (Vo1dekSelectIMP)method_getImplementation(selectM);

    // class_addMethod refuses to replace a method the class already implements,
    // and the list does implement the cell and selection callbacks itself, so the
    // replacements have to go through class_replaceMethod.
    class_replaceMethod(cls, rowsSel, (IMP)Vo1dekRowsHook, method_getTypeEncoding(rowsM));
    class_replaceMethod(cls, cellSel, (IMP)Vo1dekCellHook, method_getTypeEncoding(cellM));
    class_replaceMethod(cls, selectSel, (IMP)Vo1dekSelectHook, method_getTypeEncoding(selectM));

    Vo1dekRootList = list;
    Vo1dekInjectedIntoList = YES;

    UITableView *table = [list valueForKey:@"tableView"];
    [table reloadData];
    Vo1dekLog(@"[pane] row injected into %@ (sections %ld, rows %ld)",
              name,
              (long)[table numberOfSections],
              (long)[table numberOfRowsInSection:Vo1dekLastSection(table)]);
}

#pragma mark - Settings container hook

// A Logos %hook is installed from the constructor, long before Settings has
// loaded PSUIPrefsRootController, and a hook on a class that is not resident yet
// is silently dropped. That is why nothing was ever logged. The class name is
// polled for instead and the two callbacks are replaced directly, so the hook goes
// in at the moment the container actually exists.
static IMP Vo1dekOrigRootViewDidLoad = NULL;
static IMP Vo1dekOrigRootViewDidAppear = NULL;

static void Vo1dekTryInject(id container) {
    if (Vo1dekInjectedIntoList) return;
    if (container == nil) return;

    SEL listSel = NSSelectorFromString(@"rootListController");
    if (![container respondsToSelector:listSel]) {
        Vo1dekLog(@"[pane] %@ exposes no rootListController",
                  NSStringFromClass([(UIViewController *)container class]));
        return;
    }

    UIViewController *list = ((UIViewController * (*)(id, SEL))objc_msgSend)(container, listSel);
    if (list == nil) {
        Vo1dekLog(@"[pane] %@ has no root list yet",
                  NSStringFromClass([(UIViewController *)container class]));
        return;
    }
    Vo1dekInstallRow(list);
}

static void Vo1dekRootDidLoadHook(id self, SEL _cmd) {
    if (Vo1dekOrigRootViewDidLoad != NULL) {
        ((void (*)(id, SEL))Vo1dekOrigRootViewDidLoad)(self, _cmd);
    }
    @try {
        Vo1dekTryInject(self);
    } @catch (NSException *exception) {
        Vo1dekLog(@"[pane] injection failed: %@", exception.reason);
    }
}

static void Vo1dekRootDidAppearHook(id self, SEL _cmd, BOOL animated) {
    if (Vo1dekOrigRootViewDidAppear != NULL) {
        ((void (*)(id, SEL, BOOL))Vo1dekOrigRootViewDidAppear)(self, _cmd, animated);
    }
    @try {
        Vo1dekTryInject(self);
    } @catch (NSException *exception) {
        Vo1dekLog(@"[pane] injection failed: %@", exception.reason);
    }
}

static void Vo1dekInstallContainerHook(void) {
    if (Vo1dekOrigRootViewDidLoad != NULL) return;

    Class cls = NSClassFromString(@"PSUIPrefsRootController");
    if (cls == Nil) return;

    Method didLoad = class_getInstanceMethod(cls, @selector(viewDidLoad));
    Method didAppear = class_getInstanceMethod(cls, @selector(viewDidAppear:));
    if (didLoad == NULL || didAppear == NULL) return;

    // Both are inherited from UIViewController here, so the original
    // implementations are saved before the class gets its own copy.
    Vo1dekOrigRootViewDidLoad = method_getImplementation(didLoad);
    Vo1dekOrigRootViewDidAppear = method_getImplementation(didAppear);
    class_replaceMethod(cls, @selector(viewDidLoad), (IMP)Vo1dekRootDidLoadHook,
                        method_getTypeEncoding(didLoad));
    class_replaceMethod(cls, @selector(viewDidAppear:), (IMP)Vo1dekRootDidAppearHook,
                        method_getTypeEncoding(didAppear));
    Vo1dekLog(@"[pane] container hook installed on %@", NSStringFromClass(cls));
}

static void Vo1dekPollForContainer(void) {
    // The pane is a real PreferenceBundle, the same way every other tweak on this
    // device publishes its Settings page, so Settings builds the row itself. The
    // injection below is only the fallback for the case where that bundle is
    // missing, and running both would show the entry twice.
    NSString *root = [Vo1dekPaneBundlesPath stringByAppendingPathComponent:
                      @"WipeCode.bundle/Root.plist"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:root]) {
        Vo1dekLog(@"[pane] bundle present, Settings will list the pane itself");
        return;
    }
    Vo1dekLog(@"[pane] no bundle at %@, falling back to row injection", root);

    for (NSUInteger attempt = 0; attempt < 80; attempt++) {
        if (Vo1dekOrigRootViewDidLoad != NULL) return;
        Class cls = NSClassFromString(@"PSUIPrefsRootController");
        if (cls != Nil) {
            Vo1dekInstallContainerHook();
            if (Vo1dekOrigRootViewDidLoad != NULL) return;
        }
        [NSThread sleepForTimeInterval:0.25];
    }
    Vo1dekLog(@"[pane] PSUIPrefsRootController never became resident");
}

#pragma mark - probing

// Every loaded class name, sorted. This runs inside Preferences, which is the only
// process where the PS* Settings classes are actually resident: dumping them from
// SpringBoard reports them as missing no matter what they are called.
static NSArray<NSString *> *Vo1dekAllClassNames(void) {
    unsigned int count = objc_getClassList(NULL, 0);
    unsigned int capacity = count + 64;
    Class *buffer = (Class *)malloc(sizeof(Class) * capacity);
    if (buffer == NULL) return @[];

    count = objc_getClassList(buffer, capacity);
    NSMutableArray<NSString *> *names = [NSMutableArray arrayWithCapacity:count];
    for (unsigned int i = 0; i < count; i++) {
        const char *name = class_getName(buffer[i]);
        if (name != NULL) [names addObject:@(name)];
    }
    free(buffer);
    [names sortUsingSelector:@selector(compare:)];
    return names;
}

// Which classes implement this selector. Asking "who responds to X" is more
// reliable than guessing a class name: the web pane host was not called
// PSWebViewController here, and the previous rounds only ever dumped the names
// that had been guessed.
static void Vo1dekDumpClassesImplementing(const char *selectorName) {
    SEL sel = NSSelectorFromString(@(selectorName));
    NSMutableArray<NSString *> *hits = [NSMutableArray array];
    for (NSString *name in Vo1dekAllClassNames()) {
        Class cls = NSClassFromString(name);
        if (cls == Nil) continue;
        if (class_getInstanceMethod(cls, sel) != NULL) [hits addObject:name];
    }
    Vo1dekLog(@"[probe] classes implementing -%s: %lu", selectorName, (unsigned long)hits.count);
    for (NSString *name in hits) {
        Vo1dekLog(@"[probe]   %@", name);
    }
}

static void Vo1dekDumpMethodsOf(NSString *className) {
    Class cls = NSClassFromString(className);
    if (cls == Nil) {
        Vo1dekLog(@"[probe] class %@: NOT FOUND", className);
        return;
    }
    Vo1dekLog(@"[probe] --- methods of %@ ---", className);
    unsigned int count = 0;
    Method *inst = class_copyMethodList(cls, &count);
    for (unsigned int i = 0; i < count; i++) {
        Vo1dekLog(@"[probe]   - %s  %s", sel_getName(method_getName(inst[i])),
                  method_getTypeEncoding(inst[i]));
    }
    free(inst);
}

// What Settings actually finds in PreferenceBundles. If this comes back empty on
// a device that has other tweak panes, the directory itself is not the problem
// and the row injection is the right answer.
static void Vo1dekLogPaneBundles(void) {
    NSArray *entries = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:Vo1dekPaneBundlesPath
                                                                          error:NULL];
    Vo1dekLog(@"[probe] PreferenceBundles entries: %lu", (unsigned long)entries.count);
    for (NSString *entry in entries) {
        Vo1dekLog(@"[probe]   %@", entry);
    }
}

#define VO1DEK_PROBE_VERSION 6

static void Vo1dekRunProbeIfNeeded(void) {
    NSString *existing = [NSString stringWithContentsOfFile:VO1DEK_PROBE
                                                  encoding:NSUTF8StringEncoding
                                                     error:NULL];
    NSString *marker = [NSString stringWithFormat:@"[probe] pref done v%d", VO1DEK_PROBE_VERSION];
    if ([existing rangeOfString:marker].location != NSNotFound) return;

    Vo1dekLog(@"[probe] ==== pref run v%d ====", VO1DEK_PROBE_VERSION);

    // v1 established that PSWebViewController does not exist in this process, so a
    // PSWebView specifier can never be instantiated. v2 stops guessing names and
    // asks the runtime directly which class hosts a web pane, and records what the
    // PreferenceBundles directory actually contains.
    Vo1dekDumpClassesImplementing("setUserStyleSheet:");
    Vo1dekDumpClassesImplementing("webView:shouldStartLoadWithRequest:navigationType:");
    Vo1dekDumpClassesImplementing("loadWithFileURL:allowingReadAccessToURL:");
    Vo1dekLogPaneBundles();

    for (NSString *name in @[@"PSUIPrefsRootController", @"PSUIPrefsListController", @"PSBundleController"]) {
        Vo1dekDumpMethodsOf(name);
    }

    Vo1dekLog(@"[probe] pref done v%d", VO1DEK_PROBE_VERSION);
}

#pragma mark - result notification

static const void *Vo1dekPrefToken;

static void Vo1dekResultCallback(CFNotificationCenterRef center, void *observer,
                                 CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSDictionary *result = Vo1dekReadPlist(VO1DEK_RESULT) ?: @{};
        Vo1dekLog(@"[pref] result ok=%@ method=%@ error=%@", result[@"ok"], result[@"method"], result[@"error"]);
        Vo1dekSendStatus();
    });
}

static void Vo1dekStartSettings(void) {
    Vo1dekLog(@"[pref] Settings role active");

    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                    Vo1dekPrefToken,
                                    Vo1dekResultCallback,
                                    (__bridge CFStringRef)VO1DEK_NOTIFY_RESULT,
                                    NULL,
                                    CFNotificationSuspensionBehaviorCoalesce);

    Vo1dekLog(@"[pref] dylib path: %@",
              [NSBundle bundleForClass:[Vo1dekBridge class]].bundlePath ?: @"(unknown)");
    Vo1dekLog(@"[pref] pane html present=%d at %@",
              (int)[[NSFileManager defaultManager] fileExistsAtPath:Vo1dekPaneHTMLPath],
              Vo1dekPaneHTMLPath);

    // Deferred: enumerating every loaded class while Preferences is still setting
    // itself up is heavy, and PS* classes may not all be in yet.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        Vo1dekRunProbeIfNeeded();
    });
}

#pragma mark - hooks

%group Vo1dekListHooks

// The container hook above does the work. This group stays only so the tweak
// still has a hook section to hang off when Settings loads its classes lazily.
%hook UIViewController

- (void)viewDidAppear:(BOOL)animated {
    %orig;
}

%end

%end

#pragma mark - entry point

%ctor {
    @autoreleasepool {
        Vo1dekEnsureDir();

        // One dylib, two processes. FBSSystemService needs the com.apple.springboard
        // entitlement, so the erase has to run in SpringBoard, while the pane has to
        // run in Settings. The bundle identifier decides which half of this file is
        // live, and everything else returns immediately.
        NSString *host = [[NSBundle mainBundle] bundleIdentifier] ?: @"(none)";
        if ([host isEqualToString:@"com.apple.springboard"]) {
            Vo1dekStartSpringBoard();
        } else if ([host isEqualToString:@"com.apple.Preferences"]) {
            %init(Vo1dekListHooks);
            Vo1dekStartSettings();
            // Settings loads its own classes long after this constructor has run,
            // so the container hook goes in from a background thread that waits for
            // PSUIPrefsRootController to become resident.
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                Vo1dekPollForContainer();
            });
        } else {
            Vo1dekLog(@"[boot] loaded in %@, no role", host);
        }
    }
}
