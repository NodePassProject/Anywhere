//
//  anywhere_wolfssl_seed.c
//  Anywhere
//
//  Created by Argsment Limited on 4/16/26.
//

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
