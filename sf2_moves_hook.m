/*
 * SF2 hook — MINIMAL TEST BUILD
 * No hooks, no DYLD_INTERPOSE.
 * Just logs on load to confirm binary patching works.
 */
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

__attribute__((constructor))
static void sf2_hook_init(void) {
    NSLog(@"[SF2Hook] *** DYLIB LOADED OK *** iOS=%@",
          [[UIDevice currentDevice] systemVersion]);
}
