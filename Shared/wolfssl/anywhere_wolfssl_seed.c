/* anywhere_wolfssl_seed.c
 *
 * Entropy source for wolfSSL on Apple platforms. Wired in via
 * CUSTOM_RAND_GENERATE_SEED in user_settings.h. Routes wc_GenerateSeed through
 * Security.framework's SecRandomCopyBytes — avoids /dev/urandom, which can be
 * unreliable under the Network Extension sandbox.
 */

#include <Security/SecRandom.h>
#include <stdint.h>

int anywhere_wolfssl_seed(unsigned char *output, unsigned int sz)
{
    if (output == NULL || sz == 0) {
        return 0;
    }
    if (SecRandomCopyBytes(kSecRandomDefault, (size_t)sz, output) != errSecSuccess) {
        return -1;
    }
    return 0;
}
