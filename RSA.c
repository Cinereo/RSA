#include "BigNum.c"
#include <time.h>


/*

 */
int readFile(FILE *fd, char **buffer, int bytes) {
    int len = 0, cap = BUF_SIZE, r;
    char buf[BUF_SIZE];
    *buffer = malloc(BUF_SIZE * sizeof(char));
    while ((r = fread(buf, sizeof(char), BUF_SIZE, fd)) > 0) {
        if (len + r >= cap) {
            cap *= 2;
            *buffer = realloc(*buffer, cap);
        }
        memcpy(&(*buffer)[len], buf, r);
        len += r;
    }
    /* Pad the last block with zeros to signal end of cryptogram. An additional block is added if there is no room */
    if (len + bytes - len % bytes > cap) *buffer = realloc(*buffer, len + bytes - len % bytes);
    do {
        (*buffer)[len] = '\0';
        len++;
    } while (len % bytes != 0);
    return len;
}

void encode(bignum *m, bignum *e, bignum *n, bignum *result) {
    bignum_modpow(m, e, n, result);
}

/*

 */
void decode(bignum *c, bignum *d, bignum *n, bignum *result) {
    bignum_modpow(c, d, n, result);
}

/*

 */
bignum *encodeMessage(int len, int bytes, char *message, bignum *exponent, bignum *modulus) {

    int i, j;
    bignum *encoded = calloc(len / bytes, sizeof(bignum));
    bignum *num128 = bignum_init(), *num128pow = bignum_init();
    bignum *x = bignum_init(), *current = bignum_init();
    bignum_fromint(num128, 128);
    bignum_fromint(num128pow, 1);
    for (i = 0; i < len; i += bytes) {
        bignum_fromint(x, 0);
        bignum_fromint(num128pow, 1);

        for (j = 0; j < bytes; j++) {
            bignum_fromint(current, message[i + j]);
            bignum_imultiply(current, num128pow);
            bignum_iadd(x, current); /*x += buffer[i + j] * (1 << (7 * j)) */
            bignum_imultiply(num128pow, num128);
        }
        encode(x, exponent, modulus, &encoded[i / bytes]);
//#ifndef NOPRINT
        //bignum_print(&encoded[i / bytes]);
        //printf(" ");
//#endif
    }
    return encoded;
}

/*

 */
int *decodeMessage(int len, int bytes, bignum *cryptogram, bignum *exponent, bignum *modulus) {
    int *decoded = malloc(len * bytes * sizeof(int));
    int i, j;
    bignum *x = bignum_init(), *remainder = bignum_init();
    bignum *num128 = bignum_init();
    bignum_fromint(num128, 128);
    for (i = 0; i < len; i++) {
        decode(&cryptogram[i], exponent, modulus, x);
        for (j = 0; j < bytes; j++) {
            bignum_idivider(x, num128, remainder);
            if (remainder->length == 0) decoded[i * bytes + j] = (char) 0;
            else decoded[i * bytes + j] = (char) (remainder->data[0]);


#ifndef NOPRINT
            // printf("%c", (char) (decoded[i * bytes + j]));
#endif
        }
    }
    return decoded;
}

/*

 */
int main(void) {
    int i, bytes, len;
    bignum *p = bignum_init(), *q = bignum_init(), *n = bignum_init();
    bignum *phi = bignum_init(), *e = bignum_init(), *d = bignum_init();
    bignum *bbytes = bignum_init(), *shift = bignum_init();
    bignum *temp1 = bignum_init(), *temp2 = bignum_init();

    bignum *encoded;
    int *decoded;
    char *buffer;
    FILE *f;

    srand(time(NULL));

    randPrime(FACTOR_DIGITS, p);
    printf("Got first prime factor, p = ");
    bignum_print(p);
    printf(" ... ");
    getchar();

    randPrime(FACTOR_DIGITS, q);
    printf("Got second prime factor, q = ");
    bignum_print(q);
    printf(" ... ");
    getchar();

    bignum_multiply(n, p, q);
    printf("Got modulus, n = pq = ");
    bignum_print(n);
    printf(" ... ");
    getchar();

    bignum_subtract(temp1, p, &NUMS[1]);
    bignum_subtract(temp2, q, &NUMS[1]);
    bignum_multiply(phi, temp1, temp2); /* phi = (p - 1) * (q - 1) */
    printf("Got totient, phi = ");
    bignum_print(phi);
    printf(" ... ");
    getchar();

    randExponent(phi, EXPONENT_MAX, e);
    printf("Chose public exponent, e = ");
    bignum_print(e);
    printf("\nPublic key is (");
    bignum_print(e);
    printf(", ");
    bignum_print(n);
    printf(") ... ");
    getchar();

    bignum_inverse(e, phi, d);
    printf("Calculated private exponent, d = ");
    bignum_print(d);
    printf("\nPrivate key is (");
    bignum_print(d);
    printf(", ");
    bignum_print(n);
    printf(") ... ");
    getchar();


    bytes = -1;
    bignum_fromint(shift, 1 << 7); /* 7 bits / char */
    bignum_fromint(bbytes, 1);
    while (bignum_less(bbytes, n)) {
        bignum_imultiply(bbytes, shift);
        bytes++;
    }

    printf("Opening file \"text.txt\" for reading\n");
    f = fopen("text.txt", "r");
    if (f == NULL) {
        printf("Failed to open file \"text.txt\". Does it exist?\n");
        return EXIT_FAILURE;
    }
    len = readFile(f, &buffer, bytes); /* len will be a multiple of bytes, to send whole chunks */

    printf("File \"text.txt\" read successfully, %d bytes read. Encoding byte stream in chunks of %d bytes ... ", len,
           bytes);
    getchar();
    printf("\n");
    clock_t start = clock();
    encoded = encodeMessage(len, bytes, buffer, e, n);
    printf("\n\nEncoding finished successfully ... ");
    getchar();
    clock_t end = clock();
    float seconds = (float) (end - start);
    printf("Encoding took %f clock ticks or %f seconds \n", seconds, seconds/CLOCKS_PER_SEC);
    printf("Decoding encoded message ... ");
    getchar();
    printf("\n");
    clock_t start2 = clock();
    decoded = decodeMessage(len / bytes, bytes, encoded, d, n);
    clock_t end2 = clock();
    float seconds2 = (float) (end2 - start2);
    printf("Decoding took %f clock ticks or %f seconds\n", seconds2, seconds2/CLOCKS_PER_SEC);
    printf("\n\nFinished RSA demonstration!");

    for (i = 0; i < len / bytes; i++) free(encoded[i].data);
    free(encoded);
    free(decoded);
    free(buffer);
    bignum_deinit(p);
    bignum_deinit(q);
    bignum_deinit(n);
    bignum_deinit(phi);
    bignum_deinit(e);
    bignum_deinit(d);
    bignum_deinit(bbytes);
    bignum_deinit(shift);
    bignum_deinit(temp1);
    bignum_deinit(temp2);
    fclose(f);

    return EXIT_SUCCESS;
}
