#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <limits.h>

/* Accuracy with which we test for prime numbers using Solovay-Strassen algorithm.
 * 20 Tests should be sufficient for most largish primes */
#define ACCURACY 20

int FACTOR_DIGITS=50;
#define EXPONENT_MAX RAND_MAX
#define BUF_SIZE 1024

/* Initial capacity for a bignum structure. They will flexibly expand but this
 * should be reasonably high to avoid frequent early reallocs */
#define BIGNUM_CAPACITY 20

/* Radix and halfradix. These should be changed if the limb/word type changes */
#define RADIX 4294967296UL
#define HALFRADIX 2147483648UL

#define MAX(a, b) ((a) > (b) ? (a) : (b))

/**

 */
typedef unsigned int word;

/**

 */
typedef struct _bignum {
    int length;
    int capacity;
    word *data;
} bignum;

/**

 */
void bignum_iadd(bignum *source, bignum *add);

void bignum_add(bignum *result, bignum *b1, bignum *b2);

void bignum_isubtract(bignum *source, bignum *add);

void bignum_subtract(bignum *result, bignum *b1, bignum *b2);

void bignum_imultiply(bignum *source, bignum *add);

void bignum_multiply(bignum *result, bignum *b1, bignum *b2);

void bignum_idivide(bignum *source, bignum *div);

void bignum_idivider(bignum *source, bignum *div, bignum *remainder);

void bignum_remainder(bignum *source, bignum *div, bignum *remainder);

void bignum_imodulate(bignum *source, bignum *modulus);

void bignum_divide(bignum *quotient, bignum *remainder, bignum *b1, bignum *b2);

/**

 */
word DATA0[1] = {0};
word DATA1[1] = {1};
word DATA2[1] = {2};
word DATA3[1] = {3};
word DATA4[1] = {4};
word DATA5[1] = {5};
word DATA6[1] = {6};
word DATA7[1] = {7};
word DATA8[1] = {8};
word DATA9[1] = {9};
word DATA10[1] = {10};
bignum NUMS[11] = {{1, 1, DATA0},
                   {1, 1, DATA1},
                   {1, 1, DATA2},
                   {1, 1, DATA3},
                   {1, 1, DATA4},
                   {1, 1, DATA5},
                   {1, 1, DATA6},
                   {1, 1, DATA7},
                   {1, 1, DATA8},
                   {1, 1, DATA9},
                   {1, 1, DATA10}};

/*

 */
bignum *bignum_init() {
    bignum *b = malloc(sizeof(bignum));
    b->length = 0;
    b->capacity = BIGNUM_CAPACITY;
    b->data = calloc(BIGNUM_CAPACITY, sizeof(word));
    return b;
}

/*
 */
void bignum_deinit(bignum *b) {
    free(b->data);
    free(b);
}

/*
 */
int bignum_iszero(bignum *b) {
    return b->length == 0 || (b->length == 1 && b->data[0] == 0);
}

/*
 */
int bignum_isnonzero(bignum *b) {
    return !bignum_iszero(b);
}

/*
 */
void bignum_copy(bignum *source, bignum *dest) {
    dest->length = source->length;
    if (source->capacity > dest->capacity) {
        dest->capacity = source->capacity;
        dest->data = realloc(dest->data, dest->capacity * sizeof(word));
    }
    memcpy(dest->data, source->data, dest->length * sizeof(word));
}

/*
 */
void bignum_fromstring(bignum *b, char *string) {
    int i, len = 0;
    while (string[len] != '\0') len++; /* Find string length */
    for (i = 0; i < len; i++) {
        if (i != 0) bignum_imultiply(b, &NUMS[10]); /* Base 10 multiply */
        bignum_iadd(b, &NUMS[string[i] - '0']); /* Add */
    }
}

/*
 */
void bignum_fromint(bignum *b, unsigned int num) {
    b->length = 1;
    if (b->capacity < b->length) {
        b->capacity = b->length;
        b->data = realloc(b->data, b->capacity * sizeof(word));
    }
    b->data[0] = num;
}


/*

 */
void bignum_print(bignum *b) {
    int cap = 100, len = 0, i;
    char *buffer = malloc(cap * sizeof(char));
    bignum *copy = bignum_init(), *remainder = bignum_init();
    if (b->length == 0 || bignum_iszero(b)) printf("0");
    else {
        bignum_copy(b, copy);
        while (bignum_isnonzero(copy)) {
            bignum_idivider(copy, &NUMS[10], remainder);
            buffer[len++] = remainder->data[0];
            if (len >= cap) {
                cap *= 2;
                buffer = realloc(buffer, cap * sizeof(char));
            }
        }
        for (i = len - 1; i >= 0; i--) {
            if (buffer[i] >= 10) printf("%c", buffer[i] - 10 + 'a');
            else printf("%d", buffer[i]);
        };
    }
    bignum_deinit(copy);
    bignum_deinit(remainder);
    free(buffer);
}

char *bignum_to_string(bignum *b) {
    char *buf = malloc(10000 * sizeof(char));
    int cap = 100, len = 0, i;
    char *buffer = malloc(cap * sizeof(char));
    bignum *copy = bignum_init(), *remainder = bignum_init();
    if (b->length == 0 || bignum_iszero(b)) {
        buf[0] = '0';
        buf[1] = '\0';
    } else {
        bignum_copy(b, copy);
        while (bignum_isnonzero(copy)) {
            bignum_idivider(copy, &NUMS[10], remainder);
            buffer[len++] = remainder->data[0];
            if (len >= cap) {
                cap *= 2;
                buffer = realloc(buffer, cap * sizeof(char));
            }
        }
        int j = 0;
        for (i = len - 1; i >= 0; i--) {
            if (buffer[i] >= 10) buf[j] = (char) (buffer[i] + 'a');
            else buf[j] = (char) (buffer[i] + '0');
            j++;
        };
        buf[j] = '\0';
    }
    bignum_deinit(copy);
    bignum_deinit(remainder);
    free(buffer);
    return buf;
}


void bignum_print2(bignum *b) {
    int cap = 100, len = 0, i;
    char *buffer = malloc(cap * sizeof(char));
    bignum *copy = bignum_init(), *remainder = bignum_init();
    if (b->length == 0 || bignum_iszero(b)) printf("0");
    else {
        bignum_copy(b, copy);
        while (bignum_isnonzero(copy)) {
            bignum_idivider(copy, &NUMS[2], remainder);
            buffer[len++] = remainder->data[0];
            if (len >= cap) {
                cap *= 2;
                buffer = realloc(buffer, cap * sizeof(char));
            }
        }
        for (i = len - 1; i >= 0; i--) {
            if (buffer[i] >= 10) printf("%c", buffer[i] - 10 + 'a');
            else printf("%d", buffer[i]);
        };
    }
    bignum_deinit(copy);
    bignum_deinit(remainder);
    free(buffer);
}

/*
 */
int bignum_equal(bignum *b1, bignum *b2) {
    int i;
    if (bignum_iszero(b1) && bignum_iszero(b2)) return 1;
    else if (bignum_iszero(b1)) return 0;
    else if (bignum_iszero(b2)) return 0;
    else if (b1->length != b2->length) return 0;
    for (i = b1->length - 1; i >= 0; i--) {
        if (b1->data[i] != b2->data[i]) return 0;
    }
    return 1;
}

/*

 */
int bignum_greater(bignum *b1, bignum *b2) {
    int i;
    if (bignum_iszero(b1) && bignum_iszero(b2)) return 0;
    else if (bignum_iszero(b1)) return 0;
    else if (bignum_iszero(b2)) return 1;
    else if (b1->length != b2->length) return b1->length > b2->length;
    for (i = b1->length - 1; i >= 0; i--) {
        if (b1->data[i] != b2->data[i]) return b1->data[i] > b2->data[i];
    }
    return 0;
}

/*

 */
int bignum_less(bignum *b1, bignum *b2) {
    int i;
    if (bignum_iszero(b1) && bignum_iszero(b2)) return 0;
    else if (bignum_iszero(b1)) return 1;
    else if (bignum_iszero(b2)) return 0;
    else if (b1->length != b2->length) return b1->length < b2->length;
    for (i = b1->length - 1; i >= 0; i--) {
        if (b1->data[i] != b2->data[i]) return b1->data[i] < b2->data[i];
    }
    return 0;
}

/*

 */
int bignum_geq(bignum *b1, bignum *b2) {
    return !bignum_less(b1, b2);
}

/*

 */
int bignum_leq(bignum *b1, bignum *b2) {
    return !bignum_greater(b1, b2);
}

/**

 */
void bignum_iadd(bignum *source, bignum *add) {
    bignum *temp = bignum_init();
    bignum_add(temp, source, add);
    bignum_copy(temp, source);
    bignum_deinit(temp);
}

/*

 */
void bignum_add(bignum *result, bignum *b1, bignum *b2) {
    word sum, carry = 0;
    int i, n = MAX(b1->length, b2->length);
    if (n + 1 > result->capacity) {
        result->capacity = n + 1;
        result->data = realloc(result->data, result->capacity * sizeof(word));
    }
    for (i = 0; i < n; i++) {
        sum = carry;
        if (i < b1->length) sum += b1->data[i];
        if (i < b2->length) sum += b2->data[i];
        result->data[i] = sum; /* Already taken mod 2^32 by unsigned wrap around */

        if (i < b1->length) {
            if (sum < b1->data[i]) carry = 1; /* Result must have wrapped 2^32 so carry bit is 1 */
            else carry = 0;
        } else {
            if (sum < b2->data[i]) carry = 1; /* Result must have wrapped 2^32 so carry bit is 1 */
            else carry = 0;
        }
    }
    if (carry == 1) {
        result->length = n + 1;
        result->data[n] = 1;
    } else {
        result->length = n;
    }
}

/*

 */
void bignum_isubtract(bignum *source, bignum *sub) {
    bignum *temp = bignum_init();
    bignum_subtract(temp, source, sub);
    bignum_copy(temp, source);
    bignum_deinit(temp);
}

/*

 */
void bignum_subtract(bignum *result, bignum *b1, bignum *b2) {
    int length = 0, i;
    word carry = 0, diff, temp;
    if (b1->length > result->capacity) {
        result->capacity = b1->length;
        result->data = realloc(result->data, result->capacity * sizeof(word));
    }
    for (i = 0; i < b1->length; i++) {
        temp = carry;
        if (i < b2->length) temp = temp + b2->data[i]; /* Auto wrapped mod RADIX */
        diff = b1->data[i] - temp;
        if (temp > b1->data[i]) carry = 1;
        else carry = 0;
        result->data[i] = diff;
        if (result->data[i] != 0) length = i + 1;
    }
    result->length = length;
}

/*

 */
void bignum_imultiply(bignum *source, bignum *mult) {
    bignum *temp = bignum_init();
    bignum_multiply(temp, source, mult);
    bignum_copy(temp, source);
    bignum_deinit(temp);
}

/*

 */
void bignum_multiply(bignum *result, bignum *b1, bignum *b2) {
    int i, j, k;
    word carry, temp;
    unsigned long long int prod; /* Long for intermediate product... this is not portable and should probably be changed */
    if (b1->length + b2->length > result->capacity) {
        result->capacity = b1->length + b2->length;
        result->data = realloc(result->data, result->capacity * sizeof(word));
    }
    for (i = 0; i < b1->length + b2->length; i++) result->data[i] = 0;

    for (i = 0; i < b1->length; i++) {
        for (j = 0; j < b2->length; j++) {
            prod = (b1->data[i] * (unsigned long long int) b2->data[j]) +
                   (unsigned long long int) (result->data[i + j]); /* This should not overflow... */
            carry = (word) (prod / RADIX);

            /* Add carry to the next word over, but this may cause further overflow.. propogate */
            k = 1;
            while (carry > 0) {
                temp = result->data[i + j + k] + carry;
                if (temp < result->data[i + j + k]) carry = 1;
                else carry = 0;
                result->data[i + j + k] = temp; /* Already wrapped in unsigned arithmetic */
                k++;
            }

            prod = (result->data[i + j] + b1->data[i] * (unsigned long long int) b2->data[j]) %
                   RADIX; /* Again, should not overflow... */
            result->data[i + j] = prod; /* Add */
        }
    }
    if (b1->length + b2->length > 0 && result->data[b1->length + b2->length - 1] == 0)
        result->length =
                b1->length + b2->length -
                1;
    else result->length = b1->length + b2->length;
}

/*

 */
void bignum_idivide(bignum *source, bignum *div) {
    bignum *q = bignum_init(), *r = bignum_init();
    bignum_divide(q, r, source, div);
    bignum_copy(q, source);
    bignum_deinit(q);
    bignum_deinit(r);
}

/*

 */
void bignum_idivider(bignum *source, bignum *div, bignum *remainder) {
    bignum *q = bignum_init(), *r = bignum_init();
    bignum_divide(q, r, source, div);
    bignum_copy(q, source);
    bignum_copy(r, remainder);
    bignum_deinit(q);
    bignum_deinit(r);
}

/*

 */
void bignum_remainder(bignum *source, bignum *div, bignum *remainder) {
    bignum *q = bignum_init();
    bignum_divide(q, remainder, source, div);
    bignum_deinit(q);
}

/**

 */
void bignum_imodulate(bignum *source, bignum *modulus) {
    bignum *q = bignum_init(), *r = bignum_init();
    bignum_divide(q, r, source, modulus);
    bignum_copy(r, source);
    bignum_deinit(q);
    bignum_deinit(r);
}

/*

 */
void bignum_divide(bignum *quotient, bignum *remainder, bignum *b1, bignum *b2) {
    bignum *b2copy = bignum_init(), *b1copy = bignum_init();
    bignum *temp = bignum_init(), *temp2 = bignum_init(), *temp3 = bignum_init();
    bignum *quottemp = bignum_init();
    word carry = 0;
    int n, m, i, j, length = 0;
    unsigned long long factor = 1;
    unsigned long long gquot, gtemp, grem;
    if (bignum_less(b1, b2)) { /* Trivial case, b1/b2 = 0 iff b1 < b2. */
        quotient->length = 0;
        bignum_copy(b1, remainder);
    } else if (bignum_iszero(b1)) { /* 0/x = 0.. assuming b2 is nonzero */
        quotient->length = 0;
        bignum_fromint(remainder, 0);
    } else if (b2->length == 1) { /* Division by a single limb means we can do simple division */
        if (quotient->capacity < b1->length) {
            quotient->capacity = b1->length;
            quotient->data = realloc(quotient->data, quotient->capacity * sizeof(word));
        }
        for (i = b1->length - 1; i >= 0; i--) {
            gtemp = carry * RADIX + b1->data[i];
            gquot = gtemp / b2->data[0];
            quotient->data[i] = gquot;
            if (quotient->data[i] != 0 && length == 0) length = i + 1;
            carry = gtemp % b2->data[0];
        }
        bignum_fromint(remainder, carry);
        quotient->length = length;
    } else { /* Long division is neccessary */
        n = b1->length + 1;
        m = b2->length;
        if (quotient->capacity < n - m) {
            quotient->capacity = n - m;
            quotient->data = realloc(quotient->data, (n - m) * sizeof(word));
        }
        bignum_copy(b1, b1copy);
        bignum_copy(b2, b2copy);
        /* Normalize.. multiply by the divisor by 2 until MSB >= HALFRADIX. This ensures fast
         * convergence when guessing the quotient below. We also multiply the dividend by the
         * same amount to ensure the result does not change. */
        while (b2copy->data[b2copy->length - 1] < HALFRADIX) {
            factor *= 2;
            bignum_imultiply(b2copy, &NUMS[2]);
        }
        if (factor > 1) {
            bignum_fromint(temp, factor);
            bignum_imultiply(b1copy, temp);
        }
        /* Ensure the dividend is longer than the original (pre-normalized) divisor. If it is not
         * we introduce a dummy zero word to artificially inflate it. */
        if (b1copy->length != n) {
            b1copy->length++;
            if (b1copy->length > b1copy->capacity) {
                b1copy->capacity = b1copy->length;
                b1copy->data = realloc(b1copy->data, b1copy->capacity * sizeof(word));
            }
            b1copy->data[n - 1] = 0;
        }

        /* Process quotient by long division */
        for (i = n - m - 1; i >= 0; i--) {
            gtemp = RADIX * b1copy->data[i + m] + b1copy->data[i + m - 1];
            gquot = gtemp / b2copy->data[m - 1];
            if (gquot >= RADIX) gquot = UINT_MAX;
            grem = gtemp % b2copy->data[m - 1];
            while (grem < RADIX && gquot * b2copy->data[m - 2] >
                                   RADIX * grem + b1copy->data[i + m - 2]) { /* Should not overflow... ? */
                gquot--;
                grem += b2copy->data[m - 1];
            }
            quottemp->data[0] = gquot % RADIX;
            quottemp->data[1] = (gquot / RADIX);
            if (quottemp->data[1] != 0) quottemp->length = 2;
            else quottemp->length = 1;
            bignum_multiply(temp2, b2copy, quottemp);
            if (m + 1 > temp3->capacity) {
                temp3->capacity = m + 1;
                temp3->data = realloc(temp3->data, temp3->capacity * sizeof(word));
            }
            temp3->length = 0;
            for (j = 0; j <= m; j++) {
                temp3->data[j] = b1copy->data[i + j];
                if (temp3->data[j] != 0) temp3->length = j + 1;
            }
            if (bignum_less(temp3, temp2)) {
                bignum_iadd(temp3, b2copy);
                gquot--;
            }
            bignum_isubtract(temp3, temp2);
            for (j = 0; j < temp3->length; j++) b1copy->data[i + j] = temp3->data[j];
            for (j = temp3->length; j <= m; j++) b1copy->data[i + j] = 0;
            quotient->data[i] = gquot;
            if (quotient->data[i] != 0) quotient->length = i;
        }

        if (quotient->data[b1->length - b2->length] == 0) quotient->length = b1->length - b2->length;
        else quotient->length = b1->length - b2->length + 1;

        /* Divide by factor now to find final remainder */
        carry = 0;
        for (i = b1copy->length - 1; i >= 0; i--) {
            gtemp = carry * RADIX + b1copy->data[i];
            b1copy->data[i] = gtemp / factor;
            if (b1copy->data[i] != 0 && length == 0) length = i + 1;
            carry = gtemp % factor;
        }
        b1copy->length = length;
        bignum_copy(b1copy, remainder);
    }
    bignum_deinit(temp);
    bignum_deinit(temp2);
    bignum_deinit(temp3);
    bignum_deinit(b1copy);
    bignum_deinit(b2copy);
    bignum_deinit(quottemp);
}

/*

 */
void bignum_modpow(bignum *base, bignum *exponent, bignum *modulus, bignum *result) {
    bignum *a = bignum_init(), *b = bignum_init(), *c = bignum_init();
    bignum *discard = bignum_init(), *remainder = bignum_init();
    bignum_copy(base, a);
    bignum_copy(exponent, b);
    bignum_copy(modulus, c);
    bignum_fromint(result, 1);
    while (bignum_greater(b, &NUMS[0])) {
        if (b->data[0] & 1) {
            bignum_imultiply(result, a);
            bignum_imodulate(result, c);
        }
        bignum_idivide(b, &NUMS[2]);
        bignum_copy(a, discard);
        bignum_imultiply(a, discard);
        bignum_imodulate(a, c);
    }
    bignum_deinit(a);
    bignum_deinit(b);
    bignum_deinit(c);
    bignum_deinit(discard);
    bignum_deinit(remainder);
}

/*

 */
void bignum_gcd(bignum *b1, bignum *b2, bignum *result) {
    bignum *a = bignum_init(), *b = bignum_init(), *remainder = bignum_init();
    bignum *temp = bignum_init(), *discard = bignum_init();
    bignum_copy(b1, a);
    bignum_copy(b2, b);
    while (!bignum_equal(b, &NUMS[0])) {
        bignum_copy(b, temp);
        bignum_imodulate(a, b);
        bignum_copy(a, b);
        bignum_copy(temp, a);
    }
    bignum_copy(a, result);
    bignum_deinit(a);
    bignum_deinit(b);
    bignum_deinit(remainder);
    bignum_deinit(temp);
    bignum_deinit(discard);
}

/*

 */
void bignum_inverse(bignum *a, bignum *m, bignum *result) {
    bignum *remprev = bignum_init(), *rem = bignum_init();
    bignum *auxprev = bignum_init(), *aux = bignum_init();
    bignum *rcur = bignum_init(), *qcur = bignum_init(), *acur = bignum_init();

    bignum_copy(m, remprev);
    bignum_copy(a, rem);
    bignum_fromint(auxprev, 0);
    bignum_fromint(aux, 1);
    while (bignum_greater(rem, &NUMS[1])) {
        bignum_divide(qcur, rcur, remprev, rem);
        /* Observe we are finding the inverse in a finite field so we can use
         * a modified algorithm that avoids negative numbers here */
        bignum_subtract(acur, m, qcur);
        bignum_imultiply(acur, aux);
        bignum_iadd(acur, auxprev);
        bignum_imodulate(acur, m);

        bignum_copy(rem, remprev);
        bignum_copy(aux, auxprev);
        bignum_copy(rcur, rem);
        bignum_copy(acur, aux);
    }

    bignum_copy(acur, result);

    bignum_deinit(remprev);
    bignum_deinit(rem);
    bignum_deinit(auxprev);
    bignum_deinit(aux);
    bignum_deinit(rcur);
    bignum_deinit(qcur);
    bignum_deinit(acur);
}

/*

 */

int bignum_jacobi(bignum *ac, bignum *nc) {
    bignum *remainder = bignum_init(), *twos = bignum_init();
    bignum *temp = bignum_init(), *a = bignum_init(), *n = bignum_init();
    int mult = 1, result = 0;
    bignum_copy(ac, a);
    bignum_copy(nc, n);
    while (bignum_greater(a, &NUMS[1]) && !bignum_equal(a, n)) {
        bignum_imodulate(a, n);
        if (bignum_leq(a, &NUMS[1]) || bignum_equal(a, n)) break;
        bignum_fromint(twos, 0);
        /* Factor out multiples of two */
        while (a->data[0] % 2 == 0) {
            bignum_iadd(twos, &NUMS[1]);
            bignum_idivide(a, &NUMS[2]);
        }
        /* Coefficient for flipping */
        if (bignum_greater(twos, &NUMS[0]) && twos->data[0] % 2 == 1) {
            bignum_remainder(n, &NUMS[8], remainder);
            if (!bignum_equal(remainder, &NUMS[1]) && !bignum_equal(remainder, &NUMS[7])) {
                mult *= -1;
            }
        }
        if (bignum_leq(a, &NUMS[1]) || bignum_equal(a, n)) break;
        bignum_remainder(n, &NUMS[4], remainder);
        bignum_remainder(a, &NUMS[4], temp);
        if (!bignum_equal(remainder, &NUMS[1]) && !bignum_equal(temp, &NUMS[1])) mult *= -1;
        bignum_copy(a, temp);
        bignum_copy(n, a);
        bignum_copy(temp, n);
    }
    if (bignum_equal(a, &NUMS[1])) result = mult;
    else result = 0;
    bignum_deinit(remainder);
    bignum_deinit(twos);
    bignum_deinit(temp);
    bignum_deinit(a);
    bignum_deinit(n);
    return result;
}

/*

 */

int solovayPrime(int a, bignum *n) {
    bignum *ab = bignum_init(), *res = bignum_init(), *pow = bignum_init();
    bignum *modpow = bignum_init();
    int x, result;

    bignum_fromint(ab, a);
    x = bignum_jacobi(ab, n);
    if (x == -1) bignum_subtract(res, n, &NUMS[1]);
    else bignum_fromint(res, x);
    bignum_copy(n, pow);
    bignum_isubtract(pow, &NUMS[1]);
    bignum_idivide(pow, &NUMS[2]);
    bignum_modpow(ab, pow, n, modpow);

    result = !bignum_equal(res, &NUMS[0]) && bignum_equal(modpow, res);
    bignum_deinit(ab);
    bignum_deinit(res);
    bignum_deinit(pow);
    bignum_deinit(modpow);
    return result;
}

/*

 */
int probablePrime(bignum *n, int k) {
    if (bignum_equal(n, &NUMS[2])) return 1;
    else if (n->data[0] % 2 == 0 || bignum_equal(n, &NUMS[1])) return 0;
    while (k-- > 0) {
        if (n->length <= 1) { /* Prevent a > n */
            if (!solovayPrime(rand() % (n->data[0] - 2) + 2, n)) return 0;
        } else {
            int wit = rand() % (RAND_MAX - 2) + 2;
            if (!solovayPrime(wit, n)) return 0;
        }
    }
    return 1;
}

/*

 */
void randPrime(int numDigits, bignum *result) {
    char *string = malloc((numDigits + 1) * sizeof(char));
    int i;
    string[0] = (rand() % 9) + '1'; /* No leading zeros */
    string[numDigits - 1] = (rand() % 5) * 2 + '1'; /* Last digit is odd */
    for (i = 1; i < numDigits - 1; i++) string[i] = (rand() % 10) + '0';
    string[numDigits] = '\0';
    bignum_fromstring(result, string);
    while (1) {
        if (probablePrime(result, ACCURACY)) {
            free(string);
            return;
        }
        bignum_iadd(result, &NUMS[2]); /* result += 2 */
    }
}

/*

 */
void randExponent(bignum *phi, int n, bignum *result) {
    bignum *gcd = bignum_init();
    int e = rand() % n;
    while (1) {
        bignum_fromint(result, e);
        bignum_gcd(result, phi, gcd);
        if (bignum_equal(gcd, &NUMS[1])) {
            bignum_deinit(gcd);
            return;
        }
        e = (e + 1) % n;
        if (e <= 2) e = 3;
    }
}
