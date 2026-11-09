/*
 * SF2 v2.46.0 — Remote-Configurable Moves Unlocker
 *
 * Uses DYLD_INTERPOSE instead of fishhook — works on arm64e (A12+) and
 * iOS 15–27 without touching any read-only GOT pages.
 *
 * HOW IT WORKS
 * ------------
 * The __DATA,__interpose section tells dyld to substitute hooked_CCCrypt
 * for CCCrypt in every image EXCEPT this dylib itself.  So calling CCCrypt()
 * from inside this file calls the real function; the game's calls go to our
 * hook.  No vm_protect, no fishhook, no PAC issues.
 */

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>

/* ── DYLD_INTERPOSE macro ──────────────────────────────────────────────────── */
#define DYLD_INTERPOSE(_new, _old) \
    __attribute__((used)) \
    static struct { const void *r; const void *o; } \
    _interpose_##_old \
    __attribute__((section("__DATA,__interpose"))) \
    = { (const void *)(unsigned long)&(_new), \
        (const void *)(unsigned long)&(_old) };

/* ── CONFIG URL ───────────────────────────────────────────────────────────── */
#define SF2_CONFIG_URL @"https://raw.githubusercontent.com/Acez113/sf2-hook/main/sf2_config.json"

#define SF2_FALLBACK_JSON @"{\
\"enabled\":true,\
\"log_key\":true,\
\"patches\":[\
  {\"find\":\"locked=\\\"1\\\"\",\"replace\":\"locked=\\\"0\\\"\"},\
  {\"find\":\"IsLocked=\\\"1\\\"\",\"replace\":\"IsLocked=\\\"0\\\"\"},\
  {\"find\":\"IsOpen=\\\"0\\\"\",\"replace\":\"IsOpen=\\\"1\\\"\"},\
  {\"find\":\"IsOpened=\\\"0\\\"\",\"replace\":\"IsOpened=\\\"1\\\"\"},\
  {\"find\":\"MinLevel=\\\"[1-9][0-9]*\\\"\",\"replace\":\"MinLevel=\\\"0\\\"\",\"regex\":true}\
],\
\"target_files\":[\"moves\",\"weapons\",\"list\"]\
}"

/* ── logging ──────────────────────────────────────────────────────────────── */
#define LOG(fmt, ...) NSLog(@"[SF2Hook] " fmt, ##__VA_ARGS__)

/* ── remote config ───────────────────────────────────────────────────────── */
static NSDictionary *s_config = nil;
static dispatch_once_t s_config_once;
static dispatch_semaphore_t s_config_ready;

static NSDictionary *parseConfig(NSData *jsonData) {
    if (!jsonData) return nil;
    NSError *err = nil;
    id obj = [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:&err];
    if (err || ![obj isKindOfClass:[NSDictionary class]]) return nil;
    return (NSDictionary *)obj;
}

static void loadRemoteConfig(void) {
    dispatch_once(&s_config_once, ^{
        s_config_ready = dispatch_semaphore_create(0);

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                       dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            NSURL *url = [NSURL URLWithString:SF2_CONFIG_URL];
            NSURLSessionConfiguration *cfg =
                [NSURLSessionConfiguration ephemeralSessionConfiguration];
            cfg.timeoutIntervalForRequest = 8.0;
            NSURLSession *session = [NSURLSession sessionWithConfiguration:cfg];

            [[session dataTaskWithURL:url completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
                if (!e && d) {
                    NSDictionary *remote = parseConfig(d);
                    if (remote) {
                        s_config = remote;
                        LOG(@"Config loaded from GitHub (%lu bytes)", (unsigned long)d.length);
                    } else {
                        LOG(@"Config JSON parse failed, using fallback");
                    }
                } else {
                    LOG(@"Config fetch failed (%@), using fallback", e.localizedDescription);
                }
                if (!s_config) {
                    s_config = parseConfig([SF2_FALLBACK_JSON dataUsingEncoding:NSUTF8StringEncoding]);
                }
                dispatch_semaphore_signal(s_config_ready);
            }] resume];
        });
    });
}

static NSDictionary *getConfig(void) {
    if (!s_config) {
        dispatch_semaphore_wait(s_config_ready,
            dispatch_time(DISPATCH_TIME_NOW, 12LL * NSEC_PER_SEC));
    }
    return s_config;
}

/* ── XML patcher ─────────────────────────────────────────────────────────── */
static NSData *applyPatches(const void *bytes, size_t length, NSDictionary *config) {
    if (![(NSNumber *)config[@"enabled"] boolValue]) return nil;

    NSMutableString *xml = [[NSMutableString alloc]
        initWithBytes:bytes length:length encoding:NSUTF8StringEncoding];
    if (!xml) xml = [[NSMutableString alloc]
        initWithBytes:bytes length:length encoding:NSISOLatin1StringEncoding];
    if (!xml) return nil;

    NSArray *patches = config[@"patches"];
    NSUInteger total = 0;

    for (NSDictionary *p in patches) {
        NSString *find    = p[@"find"];
        NSString *replace = p[@"replace"];
        BOOL      isRegex = [p[@"regex"] boolValue];
        if (!find || !replace) continue;

        if (isRegex) {
            NSError *err = nil;
            NSRegularExpression *re = [NSRegularExpression
                regularExpressionWithPattern:find options:0 error:&err];
            if (err) { LOG(@"regex error for %@: %@", find, err); continue; }
            NSUInteger n = [re replaceMatchesInString:xml options:0
                                               range:NSMakeRange(0, xml.length)
                                        withTemplate:replace];
            if (n) { LOG(@"  [regex] %@ -> %@ x%lu", find, replace, (unsigned long)n); total += n; }
        } else {
            NSUInteger n = 0;
            NSRange sr = NSMakeRange(0, xml.length);
            NSRange found;
            while ((found = [xml rangeOfString:find options:0 range:sr]).location != NSNotFound) {
                [xml replaceCharactersInRange:found withString:replace];
                n++;
                NSUInteger next = found.location + replace.length;
                sr = NSMakeRange(next, xml.length - next);
            }
            if (n) { LOG(@"  %@ -> %@ x%lu", find, replace, (unsigned long)n); total += n; }
        }
    }

    LOG(@"Total patches applied: %lu", (unsigned long)total);
    return total > 0 ? [xml dataUsingEncoding:NSUTF8StringEncoding] : nil;
}

/* ─────────────────────────────────────────────────────────────────────────── *
 * HOOKED FUNCTIONS
 * Calling CCCrypt / CCKeyDerivationPBKDF / CCCryptorCreate from WITHIN this
 * dylib calls the real function (our image is excluded from our own interpose).
 * ─────────────────────────────────────────────────────────────────────────── */

static CCCryptorStatus hooked_CCCrypt(
    CCOperation     op,
    CCAlgorithm     alg,
    CCOptions       opts,
    const void     *key,          size_t keyLen,
    const void     *iv,
    const void     *dataIn,       size_t dataInLen,
    void           *dataOut,      size_t dataOutAvailable,
    size_t         *dataOutMoved)
{
    /* Call the real CCCrypt (our image is excluded from the interpose) */
    CCCryptorStatus status = CCCrypt(op, alg, opts, key, keyLen, iv,
                                      dataIn, dataInLen,
                                      dataOut, dataOutAvailable, dataOutMoved);

    if (status != kCCSuccess)   return status;
    if (op  != kCCDecrypt)      return status;
    if (alg != kCCAlgorithmAES) return status;
    if (keyLen != 32)           return status;

    size_t outLen = dataOutMoved ? *dataOutMoved : dataOutAvailable;
    if (outLen < 6) return status;

    const uint8_t *o = (const uint8_t *)dataOut;
    if (!(o[0]=='<' && o[1]=='?' && o[2]=='x' && o[3]=='m' && o[4]=='l'))
        return status;

    NSDictionary *cfg = getConfig();
    if (!cfg) return status;

    if ([(NSNumber *)cfg[@"log_key"] boolValue]) {
        static dispatch_once_t once;
        dispatch_once(&once, ^{
            NSString *keyHx = [NSData dataWithBytes:key length:keyLen].description;
            NSString *ivHx  = iv ? [NSData dataWithBytes:iv length:16].description : @"(zero)";
            LOG(@"=== CCCrypt AES-256-CBC decrypt ===");
            LOG(@"  key: %@", keyHx);
            LOG(@"  iv:  %@", ivHx);
        });
    }

    NSArray *targets = cfg[@"target_files"];
    if (targets && [targets count] > 0) {
        NSString *prefix = [[NSString alloc] initWithBytes:dataOut
                                                    length:MIN(outLen, 1024)
                                                  encoding:NSUTF8StringEncoding];
        BOOL match = NO;
        for (NSString *t in targets) {
            if ([prefix containsString:t]) { match = YES; break; }
        }
        if (!match) return status;
    }

    LOG(@"Target XML detected (%zu bytes) - applying patches...", outLen);

    if ([(NSNumber *)cfg[@"dump_xml"] boolValue]) {
        NSString *dump = [[NSString alloc] initWithBytes:dataOut
                                                  length:MIN(outLen, 3000)
                                                encoding:NSUTF8StringEncoding];
        LOG(@"=== XML DUMP (first 3000 chars) ===\n%@", dump ?: @"(non-utf8)");
    }

    NSData *patched = applyPatches(dataOut, outLen, cfg);
    if (!patched) return status;

    size_t pLen = patched.length;
    if (pLen > dataOutAvailable) {
        LOG(@"WARNING: patched size %zu > buffer %zu, truncating", pLen, dataOutAvailable);
        pLen = dataOutAvailable;
    }
    memcpy(dataOut, patched.bytes, pLen);
    if (dataOutMoved) *dataOutMoved = pLen;

    return status;
}

static int hooked_CCKeyDerivationPBKDF(
    CCPBKDFAlgorithm algo,
    const char *password, size_t passwordLen,
    const uint8_t *salt, size_t saltLen,
    CCPseudoRandomAlgorithm prf,
    uint32_t rounds,
    uint8_t *derivedKey, size_t derivedKeyLen)
{
    int rc = CCKeyDerivationPBKDF(algo, password, passwordLen,
                                   salt, saltLen, prf, rounds,
                                   derivedKey, derivedKeyLen);

    NSDictionary *cfg = s_config;
    if (!cfg || ![(NSNumber *)cfg[@"log_key"] boolValue]) return rc;

    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *pwd    = [[NSString alloc] initWithBytes:password length:passwordLen
                                                  encoding:NSUTF8StringEncoding];
        NSString *saltHx = [NSData dataWithBytes:salt length:saltLen].description;
        NSString *keyHx  = [NSData dataWithBytes:derivedKey length:derivedKeyLen].description;
        LOG(@"=== CCKeyDerivationPBKDF ===");
        LOG(@"  password (%zu B): %@", passwordLen, pwd ?: @"(non-utf8)");
        LOG(@"  salt     (%zu B): %@", saltLen, saltHx);
        LOG(@"  rounds=%u  keyLen=%zu", rounds, derivedKeyLen);
        LOG(@"  derived key: %@", keyHx);
    });

    return rc;
}

static CCCryptorStatus hooked_CCCryptorCreate(
    CCOperation  op,
    CCAlgorithm  alg,
    CCOptions    opts,
    const void  *key,  size_t keyLen,
    const void  *iv,
    CCCryptorRef *ref)
{
    CCCryptorStatus st = CCCryptorCreate(op, alg, opts, key, keyLen, iv, ref);

    if (st == kCCSuccess && op == kCCDecrypt && alg == kCCAlgorithmAES && keyLen == 32) {
        NSDictionary *cfg = s_config;
        if (cfg && [(NSNumber *)cfg[@"log_key"] boolValue]) {
            static dispatch_once_t once;
            dispatch_once(&once, ^{
                NSString *keyHx = [NSData dataWithBytes:key length:keyLen].description;
                LOG(@"=== CCCryptorCreate AES-256-CBC key: %@", keyHx);
            });
        }
    }
    return st;
}

/* ── register interposes ─────────────────────────────────────────────────── */
DYLD_INTERPOSE(hooked_CCCrypt,              CCCrypt)
DYLD_INTERPOSE(hooked_CCKeyDerivationPBKDF, CCKeyDerivationPBKDF)
DYLD_INTERPOSE(hooked_CCCryptorCreate,      CCCryptorCreate)

/* ── constructor: kick off config fetch with 1s delay ────────────────────── */
__attribute__((constructor))
static void sf2_hook_init(void) {
    LOG(@"SF2 hook loaded (DYLD_INTERPOSE) - fetching config in 1s...");
    loadRemoteConfig();
}
