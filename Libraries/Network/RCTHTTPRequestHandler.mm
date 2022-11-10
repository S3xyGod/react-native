/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#import <React/RCTHTTPRequestHandler.h>

#import <mutex>
#import <MMKV/MMKV.h>
#import <React/RCTNetworking.h>
#import <ReactCommon/RCTTurboModule.h>
#import <SDWebImage/SDWebImageDownloader.h>

#import "RCTNetworkPlugins.h"
#import "SecureStorage.h"

@interface RCTHTTPRequestHandler () <NSURLSessionDataDelegate, RCTTurboModule>

@end

@implementation RCTHTTPRequestHandler
{
  NSMapTable *_delegates;
  NSURLSession *_session;
  std::mutex _mutex;
}

@synthesize bridge = _bridge;
@synthesize methodQueue = _methodQueue;

RCT_EXPORT_MODULE()

- (void)invalidate
{
  std::lock_guard<std::mutex> lock(_mutex);
  [self->_session invalidateAndCancel];
  self->_session = nil;
}

// Needs to lock before call this method.
- (BOOL)isValid
{
  // if session == nil and delegates != nil, we've been invalidated
  return _session || !_delegates;
}

#pragma mark - NSURLRequestHandler

- (BOOL)canHandleRequest:(NSURLRequest *)request
{
  static NSSet<NSString *> *schemes = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    // technically, RCTHTTPRequestHandler can handle file:// as well,
    // but it's less efficient than using RCTFileRequestHandler
    schemes = [[NSSet alloc] initWithObjects:@"http", @"https", nil];
  });
  return [schemes containsObject:request.URL.scheme.lowercaseString];
}

-(NSURLCredential *)getUrlCredential:(NSURLAuthenticationChallenge *)challenge path:(NSString *)path password:(NSString *)password
{
  NSString *authMethod = [[challenge protectionSpace] authenticationMethod];
  SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;

  if ([authMethod isEqualToString:NSURLAuthenticationMethodServerTrust] || path == nil || password == nil) {
    return [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
  } else if (path && password) {
    NSMutableArray *policies = [NSMutableArray array];
    [policies addObject:(__bridge_transfer id)SecPolicyCreateSSL(true, (__bridge CFStringRef)challenge.protectionSpace.host)];
    SecTrustSetPolicies(serverTrust, (__bridge CFArrayRef)policies);

    SecTrustResultType result;
    SecTrustEvaluate(serverTrust, &result);

    if (![[NSFileManager defaultManager] fileExistsAtPath:path])
    {
      return [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
    }

    NSData *p12data = [NSData dataWithContentsOfFile:path];
    NSDictionary* options = @{ (id)kSecImportExportPassphrase:password };
    CFArrayRef rawItems = NULL;
    OSStatus status = SecPKCS12Import((__bridge CFDataRef)p12data,
                                      (__bridge CFDictionaryRef)options,
                                      &rawItems);

    if (status != noErr) {
      return [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
    }

    NSArray* items = (NSArray*)CFBridgingRelease(rawItems);
    NSDictionary* firstItem = nil;
    if ((status == errSecSuccess) && ([items count]>0)) {
        firstItem = items[0];
    }

    SecIdentityRef identity = (SecIdentityRef)CFBridgingRetain(firstItem[(id)kSecImportItemIdentity]);
    SecCertificateRef certificate = NULL;
    if (identity) {
        SecIdentityCopyCertificate(identity, &certificate);
        if (certificate) { CFRelease(certificate); }
    }

    NSMutableArray *certificates = [[NSMutableArray alloc] init];
    [certificates addObject:CFBridgingRelease(certificate)];

    [SDWebImageDownloader sharedDownloader].config.urlCredential = [NSURLCredential credentialWithIdentity:identity certificates:certificates persistence:NSURLCredentialPersistenceNone];

    return [NSURLCredential credentialWithIdentity:identity certificates:certificates persistence:NSURLCredentialPersistenceNone];
  }

  return [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
}

- (NSString *)stringToHex:(NSString *)string
{
  char *utf8 = (char *)[string UTF8String];
  NSMutableString *hex = [NSMutableString string];
  while (*utf8) [hex appendFormat:@"%02X", *utf8++ & 0x00FF];

  return [[NSString stringWithFormat:@"%@", hex] lowercaseString];
}

-(void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler {

  NSString *host = challenge.protectionSpace.host;

  // Read the clientSSL info from MMKV
  __block NSString *clientSSL;
  SecureStorage *secureStorage = [[SecureStorage alloc] init];

  // https://github.com/ammarahm-ed/react-native-mmkv-storage/blob/master/src/loader.js#L31
  NSString *key = [secureStorage getSecureKey:[self stringToHex:@"com.MMKV.default"]];

  if (key == NULL) {
    return;
  }

  NSURLCredential *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
  NSData *cryptKey = [key dataUsingEncoding:NSUTF8StringEncoding];
  MMKV *mmkv = [MMKV mmkvWithID:@"default" cryptKey:cryptKey mode:MMKVMultiProcess];
  clientSSL = [mmkv getStringForKey:host];

  if (clientSSL) {
    NSData *data = [clientSSL dataUsingEncoding:NSUTF8StringEncoding];
    id dict = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    NSString *path = [dict objectForKey:@"path"];
    NSString *password = [dict objectForKey:@"password"];
    credential = [self getUrlCredential:challenge path:path password:password];
  }

  completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
}


- (NSURLSessionDataTask *)sendRequest:(NSURLRequest *)request
                         withDelegate:(id<RCTURLRequestDelegate>)delegate
{
  std::lock_guard<std::mutex> lock(_mutex);
  // Lazy setup
  if (!_session && [self isValid]) {
    // You can override default NSURLSession instance property allowsCellularAccess (default value YES)
    //  by providing the following key to your RN project (edit ios/project/Info.plist file in Xcode):
    // <key>ReactNetworkForceWifiOnly</key>    <true/>
    // This will set allowsCellularAccess to NO and force Wifi only for all network calls on iOS
    // If you do not want to override default behavior, do nothing or set key with value false
    NSDictionary *infoDictionary = [[NSBundle mainBundle] infoDictionary];
    NSNumber *useWifiOnly = [infoDictionary objectForKey:@"ReactNetworkForceWifiOnly"];

    NSOperationQueue *callbackQueue = [NSOperationQueue new];
    callbackQueue.maxConcurrentOperationCount = 1;
    callbackQueue.underlyingQueue = [[_bridge networking] methodQueue];
    NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration defaultSessionConfiguration];
    // Set allowsCellularAccess to NO ONLY if key ReactNetworkForceWifiOnly exists AND its value is YES
    if (useWifiOnly) {
      configuration.allowsCellularAccess = ![useWifiOnly boolValue];
    }
    [configuration setHTTPShouldSetCookies:YES];
    [configuration setHTTPCookieAcceptPolicy:NSHTTPCookieAcceptPolicyAlways];
    [configuration setHTTPCookieStorage:[NSHTTPCookieStorage sharedHTTPCookieStorage]];
    _session = [NSURLSession sessionWithConfiguration:configuration
                                             delegate:self
                                        delegateQueue:callbackQueue];

    _delegates = [[NSMapTable alloc] initWithKeyOptions:NSPointerFunctionsStrongMemory
                                           valueOptions:NSPointerFunctionsStrongMemory
                                               capacity:0];
  }
  NSURLSessionDataTask *task = [_session dataTaskWithRequest:request];
  [_delegates setObject:delegate forKey:task];
  [task resume];
  return task;
}

- (void)cancelRequest:(NSURLSessionDataTask *)task
{
  {
    std::lock_guard<std::mutex> lock(_mutex);
    [_delegates removeObjectForKey:task];
  }
  [task cancel];
}

#pragma mark - NSURLSession delegate

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
   didSendBodyData:(int64_t)bytesSent
    totalBytesSent:(int64_t)totalBytesSent
totalBytesExpectedToSend:(int64_t)totalBytesExpectedToSend
{
  id<RCTURLRequestDelegate> delegate;
  {
    std::lock_guard<std::mutex> lock(_mutex);
    delegate = [_delegates objectForKey:task];
  }
  [delegate URLRequest:task didSendDataWithProgress:totalBytesSent];
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
willPerformHTTPRedirection:(NSHTTPURLResponse *)response
        newRequest:(NSURLRequest *)request
 completionHandler:(void (^)(NSURLRequest *))completionHandler
{
  // Reset the cookies on redirect.
  // This is necessary because we're not letting iOS handle cookies by itself
  NSMutableURLRequest *nextRequest = [request mutableCopy];

  NSArray<NSHTTPCookie *> *cookies = [[NSHTTPCookieStorage sharedHTTPCookieStorage] cookiesForURL:request.URL];
  nextRequest.allHTTPHeaderFields = [NSHTTPCookie requestHeaderFieldsWithCookies:cookies];
  completionHandler(nextRequest);
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)task
didReceiveResponse:(NSURLResponse *)response
 completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler
{
  id<RCTURLRequestDelegate> delegate;
  {
    std::lock_guard<std::mutex> lock(_mutex);
    delegate = [_delegates objectForKey:task];
  }
  [delegate URLRequest:task didReceiveResponse:response];
  completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)task
    didReceiveData:(NSData *)data
{
  id<RCTURLRequestDelegate> delegate;
  {
    std::lock_guard<std::mutex> lock(_mutex);
    delegate = [_delegates objectForKey:task];
  }
  [delegate URLRequest:task didReceiveData:data];
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error
{
  id<RCTURLRequestDelegate> delegate;
  {
    std::lock_guard<std::mutex> lock(_mutex);
    delegate = [_delegates objectForKey:task];
    [_delegates removeObjectForKey:task];
  }
  [delegate URLRequest:task didCompleteWithError:error];
}

@end

Class RCTHTTPRequestHandlerCls(void) {
  return RCTHTTPRequestHandler.class;
}
