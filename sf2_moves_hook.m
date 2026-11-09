/*
 * SF2 v2.46.0 — Remote-Configurable Moves Unlocker
 *
 * Uses DYLD_INTERPOSE — works on arm64e (A12+) and iOS 15-27 without
 * touching any read-only GOT pages.
 *
 * IMPORTANT: DYLD_INTERPOSE fires BEFORE constructors run.  Any call
 * to CCCrypt from another framework's constructor would arrive at our
 * hook before sf2_hook_init() has executed.  All shared state (the
 * config semaphore, s_config, etc.) must be safe to access before the
 * constructor runs.  We handle this with a pthread_once-based lazy init
 * that is safe to call from any thread at any time.
 */

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

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

#define LOG(fmt, ...) NSLog(@"[SF2Hook] " fmt, ##__VA_ARGS__)

/* ── config: thread-safe lazy init via pthread_once ───────────────────────── */
static pthread_once_t  s_once    = PTHREAD_ONCE_INIT;
static NSDictionary   *s_config  = nil;  /* nil until network or fallback */
static dispatch_semaphore_t s_sem = nil; /* signals when config is ready   */

static NSDictionary *parseConfig(NSData *d) {
    if (!d) return nil;
    NSError *e = nil;
    id obj = [NSJSONSerialization JSONObjectWithData:d options:0 error:&e];
    return (!e && [obj isKindOfClass:[NSDictionary class]]) ? obj : nil;
}

/* Called once, from any thread, safe even before constructor. */
static void initConfig(void) {
    s_sem = dispatch_semaphore_create(0);

    /* Kick off network fetch after 2-second delay so runtime is fully ready */
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2LL * NSEC_PER_SEC),
                   dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @try {
            NSURL *url = [NSURL URLWithString:SF2_CONFIG_URL];
            NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
            cfg.timeoutIntervalForRequest = 8.0;
            NSURLSession *sess = [NSURLSession sessionWithConfiguration:cfg];
            [[sess dataTaskWithURL:url completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
                if (!e && d) {
                    NSDictionary *remote = parseConfig(d);
                    if (remote) {
                        s_config = remote;
                        LOG(@"Config loaded from GitHub (%lu bytes)", (unsigned long)d.length);
                    }
                }
                if (!s_config) {
                    LOG(@"Using fallback config");
                    s_config = parseConfig([SF2_FALLBACK_JSON dataUsingEncoding:NSUTF8StringEncoding]);
                }
                dispatch_semaphore_signal(s_sem);
            }] resume];
        } @catch (NSException *ex) {
            LOG(@"Config fetch exception: %@", ex);
            s_config = parseConfig([SF2_FALLBACK_JSON dataUsingEncoding:NSUTF8StringEncoding]);
            dispatch_semaphore_signal(s_sem);
        }
    });
}

/* Get config — safe to call before constructor, from any thread. */
static NSDictionary *getConfig(void) {
    /* Trigger lazy init if not already done */
    pthread_once(&s_once, initConfig);

    if (!s_config && s_sem) {
        /* Wait for network fetch (or fallback) — max 12 seconds */
        dispatch_semaphore_wait(s_sem, dispatch_time(DISPATCH_TIME_NOW, 12LL * NSEC_PER_SEC));
        /* Restore semaphore so subsequent callers don't block */
        dispatch_semaphore_signal(s_sem);
    }
    if (!s_config) {
        /* Last resort inline fallback — should never happen */
        s_config = parseConfig([SF2_FALLBACK_JSON dataUsingEncoding:NSUTF8StringEncoding]);
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

    NSUInteger total = 0;
    for (NSDictionary *p in (NSArray *)config[@"patches"]) {
        NSString *find    = p[@"find"];
        NSString *replace = p[@"replace"];
        BOOL      isRegex = [p[@"regex"] boolValue];
        if (!find || !replace) continue;

        if (isRegex) {
            NSError *err = nil;
            NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:find
                                                                                options:0 error:&err];
            if (err) continue;
            NSUInteger n = [re replaceMatchesInString:xml options:0
                                               range:NSMakeRange(0, xml.length)
                                        withTemplate:replace];
            if (n) { LOG(@"  [regex] %@ -> %@ x%lu", find, replace, (unsigned long)n); total += n; }
        } else {
            NSUInteger n = 0;
            NSRange sr = NSMakeRange(0, xml.length), found;
            while ((found = [xml rangeOfString:find options:0 range:sr]).location != NSNotFound) {
                [xml replaceCharactersInRange:found withString:replace];
                n++;
                NSUInteger next = found.location + replace.length;
                sr = NSMakeRange(next, xml.length - next);
            }
            if (n) { LOG(@"  %@ -> %@ x%lu", find, replace, (unsigned long)n); total += n; }
        }
    }
    LOG(@"Total patches: %lu", (unsigned long)total);
    return total > 0 ? [xml dataUsingEncoding:NSUTF8StringEncoding] : nil;
}

/* ── Hooked functions ────────────────────────────────────────────────────── *
 * Calling CCCrypt / CCKeyDerivationPBKDF / CCCryptorCreate from within THIS
 * dylib calls the REAL function — dyld excludes the defining image from its
 * own interpose table (confirmed in dyld4 JustInTimeLoader.cpp).
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
    CCCryptorStatus status = CCCrypt(op, alg, opts, key, keyLen, iv,
                                      dataIn, dataInLen,
                                      dataOut, dataOutAvailable, dataOutMoved);

    @try {
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
                LOG(@"=== CCCrypt AES-256 key: %@",
                    [NSData dataWithBytes:key length:keyLen].description);
            });
        }

        NSArray *targets = cfg[@"target_files"];
        if (targets.count > 0) {
            NSString *prefix = [[NSString alloc] initWithBytes:dataOut
                                                        length:MIN(outLen, 1024)
                                                      encoding:NSUTF8StringEncoding];
            BOOL match = NO;
            for (NSString *t in targets) { if ([prefix containsString:t]) { match = YES; break; } }
            if (!match) return status;
        }

        LOG(@"Target XML (%zu B) - patching...", outLen);

        if ([(NSNumber *)cfg[@"dump_xml"] boolValue]) {
            NSString *dump = [[NSString alloc] initWithBytes:dataOut
                                                      length:MIN(outLen, 3000)
                                                    encoding:NSUTF8StringEncoding];
            LOG(@"=== XML DUMP ===\n%@", dump ?: @"(non-utf8)");
        }

        NSData *patched = applyPatches(dataOut, outLen, cfg);
        if (!patched) return status;

        size_t pLen = MIN(patched.length, dataOutAvailable);
        memcpy(dataOut, patched.bytes, pLen);
        if (dataOutMoved) *dataOutMoved = pLen;
    } @catch (NSException *ex) {
        LOG(@"hooked_CCCrypt exception: %@", ex);
    }

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
    @try {
        NSDictionary *cfg = s_config; /* non-blocking: may be nil early, that's fine */
        if (cfg && [(NSNumber *)cfg[@"log_key"] boolValue]) {
            static dispatch_once_t once;
            dispatch_once(&once, ^{
                LOG(@"=== CCKeyDerivationPBKDF pw=%zu salt=%zu rounds=%u",
                    passwordLen, saltLen, rounds);
            });
        }
    } @catch (...) {}
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
    @try {
        if (st == kCCSuccess && op == kCCDecrypt && alg == kCCAlgorithmAES && keyLen == 32) {
            NSDictionary *cfg = s_config;
            if (cfg && [(NSNumber *)cfg[@"log_key"] boolValue]) {
                static dispatch_once_t once;
                dispatch_once(&once, ^{
                    LOG(@"=== CCCryptorCreate AES-256 key: %@",
                        [NSData dataWithBytes:key length:keyLen].description);
                });
            }
        }
    } @catch (...) {}
    return st;
}

/* ── register interposes ─────────────────────────────────────────────────── */
DYLD_INTERPOSE(hooked_CCCrypt,              CCCrypt)
DYLD_INTERPOSE(hooked_CCKeyDerivationPBKDF, CCKeyDerivationPBKDF)
DYLD_INTERPOSE(hooked_CCCryptorCreate,      CCCryptorCreate)

/* ── constructor: runs after framework constructors ─────────────────────── */
__attribute__((constructor))
static void sf2_hook_init(void) {
    LOG(@"SF2 hook constructor running");
    /* Trigger the lazy init (safe to call even if already called by hook) */
    pthread_once(&s_once, initConfig);
    LOG(@"SF2 hook ready");
}
