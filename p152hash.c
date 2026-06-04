/*
p152hash.c

Sponge-based cryptographic hash function using a custom 48-byte permutation (p152).

Implements:
- Sponge construction (absorb/squeeze phases)
- Bitwise padding (10*1 rule)
- Custom permutation function over 48-byte state

Educational implementation of hash function design principles.
*/

#include <stdint.h>
#include <string.h>

/* n must be 1-31 as a shift of 32 or more has undefined behavior */
uint32_t rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32-n));

}

/* blk is a ptr to a 48 byte block, treated as array of 12 uint32_t.
 * xidx, yidx, zidx are the indices of the elements to mix
 */
void mix(uint32_t *blk, int xidx, int yidx, int zidx) {
    /* Your code for mix goes here */
    // Step 1: ROTL x & y
    // x and y have two states: modified and unmodified, z has one state
    // Unmodified
    uint32_t x = rotl(blk[xidx], 24);
    uint32_t y = rotl(blk[yidx], 9);
    uint32_t z = blk[zidx];
    // Modified
    uint32_t mx = x;
    uint32_t my = y;

    // Step 2: Shift z left by 1 and XOR with modified x
    mx = mx ^ (z << 1);
    // Step 3: AND unmodified y with z, take the result and left shift by two, 
    // then xor with modified x
    mx = mx ^ ((y & z) << 2);
    // Step 4: Take unmodified x and XOR with modified y
    my = x ^ my;
    // Step 5: Take unmodified x and OR it with z, take the result and left shift by 1
    // Take the result and XOR it with modified y
    my = my ^ ((x | z) << 1);
    // Step 6: Take unmodified y and XOR with z
    z = y ^ z;
    // Step 7: Take unmodified x and AND with unmodified y. 
    // Take the result and left shift 3. Take the result and XOR with z
    z = z ^ ((x & y) << 3);
    // Step 8: Assign new values into original buffer
    blk[xidx] = z;
    blk[yidx] = my;
    blk[zidx] = mx;
}

/* Perform p152 permutation on 48-byte input buffer "in" and write 48-byte
 * result to buffer "out". In and out may be the same or different buffers.
 * The two memcpys are not optimal but simplify the code.
 */
void p152(void *in, void *out) {
    uint32_t buf[12];
    memcpy(buf, in, 48);
    /* Your code that calls mix goes here */
    for (int i = 0; i < 24; i++) {
        mix(buf, 0, 4, 8);
        mix(buf, 1, 5, 9);
        mix(buf, 2, 6, 10);
        mix(buf, 3, 7, 11);

        uint32_t tmp = 0;
        if ((i % 4) == 0) {
            // Swap idx 0 and 1
            tmp = buf[1];
            buf[1] = buf[0];
            buf[0] = tmp;
            // Swap idx 2 and 3
            tmp = buf[3];
            buf[3] = buf[2];
            buf[2] = tmp;
            // XOR idx 0 with 0xb7e15100
            buf[0] = buf[0] ^ 0xb7e15100;
            // XOR idx 0 with i
            buf[0] = buf[0] ^ i;
        }
        if ((i % 4) == 2) {
            // Swap idx 0 and 2
            tmp = buf[2];
            buf[2] = buf[0];
            buf[0] = tmp;

            // Swap idx 1 and 3
            tmp = buf[3];
            buf[3] = buf[1];
            buf[1] = tmp;
        }
    }
    memcpy(out, buf, 48);
}


#define R 16       /* The rate of the sponge     */
#define C 32       /* The capacity of the sponge */
#define BLKLEN 48  /* Input length of p152, R+C  */


/* Perform sponge hash using p152 
    in:     pointer to the message bytes
    inlen:  length of message (number of bytes)
    out:    where the hash output goes
    outlen: length of hash output
*/

void p152hash(void *in, int inlen, void *out, int outlen) {
    unsigned char block[BLKLEN]; // Create 48 byte array. r + c = b
    unsigned char *pout = out; // pointer to hash output
    unsigned char *pin = in; // pointer to message bytes

    // Initialize block to all zeros 
    memset(block, 0x00, BLKLEN);

    // -----------------ABSORB PHASE -----------------------------------------------
    //while R or more bytes remain to be consumed
    while (inlen >= R) {
        //xor next R bytes into beginning of block
        for (int i = 0; i < R; i++) {
            block[i] = block[i] ^ pin[i];
        }

        // Advance message pointer and shrink message length by R
        pin = pin + R;
        inlen = inlen - R;
        //p152 block
        p152(block, block);
    }

    //xor any remaining bytes into begining of block
    if (inlen > 0) { // if there are still message bytes that have not been consumed
        for (int i = 0; i < inlen; i++) {
            block[i] = block[i] ^ pin[i];
        }
    }

    //xor 10*1 into appropriate places of block
    if (inlen < R) {
        // If the message length is less than R we still have room to pad
        // so the last block can be absorbed
        // XOR 1 into the MSB of the first unused byte
        block[inlen] = block[inlen] ^ 0x80; // 0x80 = 1000 0000
    }
    else {
        // Otherwise we need to create a new block of length R and fill with 0's
        memset(block, 0, R);
        // XOR 1 into the MSB of the first unused byte
        block[0] = block[0] ^ 0x80; // 0x80 = 1000 0000
    }
    // XOR 1 at the last byte of the block
    block[R - 1] = block[R - 1] ^ 0x01;
    
    //p152 block
    p152(block, block);
    //---------------------------------------------------------------------------------

    //-------------------------SQUEEZE PHASE-------------------------------------------
    //while more than R bytes remain to be output
    while (outlen > R) {
        //output R bytes from beginning of block
        for (int i = 0; i < R; i++) {
            pout[i] = block[i];
        }

        // Advance output pointer and shrink output length by R
        pout = pout + R;
        outlen = outlen - R;
        //p152 block
        p152(block,block);
    }
    //output any remaining bytes from beginning of block
    if (outlen > 0) {
        for (int i = 0; i < outlen; i++) {
            pout[i] = block[i];
        }
    }
}


#if 1
#include <stdio.h>

/* pbuf is used to print sequences of bytes from in memory */
void pbuf(void *p, int len, char *s)
{
    if (s)
        printf("%s", s);

    for (int i=0; i<len; i++)
        printf("%02X", ((unsigned char *)p)[i]);

    printf("\n");

}


int main() {
    unsigned char buf[48];
    unsigned char out[48];

    for (int i=0; i<48; i++)
        buf[i] = (unsigned char)(i + 128);


    p152hash(buf, 0, out, 36);
    pbuf(out, 36, "0 : ");

    p152hash(buf, 1, out, 36);
    pbuf(out, 36, "1 : ");

    p152hash(buf, 11, out, 36);
    pbuf(out, 36, "11: ");

    p152hash(buf, 12, out, 36);
    pbuf(out, 36, "12: ");

    p152hash(buf, 23, out, 36);
    pbuf(out, 36, "23: ");

    p152hash(buf, 24, out, 36);
    pbuf(out, 36, "24: ");

    p152hash(buf, 47, out, 36);
    pbuf(out, 36, "47: ");

    p152hash(buf, 48, out, 36);
    pbuf(out, 36, "48: ");

    printf("------------Further Testing------------\n");

    printf("Test message length = sponge rate (full block)\n");
    p152hash(buf, 16, out, 36);
    pbuf(out, 36, "16: ");

    printf("Test message length = twice the sponge rate (2 full blocks)\n");
    p152hash(buf, 32, out, 36);
    pbuf(out, 36, "32: ");


    printf("Test all zero input\n");
    for (int i = 0; i < 48; i++) {
        buf[i] = 0;
    }
    p152hash(buf, 25, out, 36);
    pbuf(out, 36, "25:");
    printf("Rerun: if hashes are different then padding was not handled correctly\n");
    p152hash(buf, 25, out, 36);
    pbuf(out, 36, "25:");

    printf("Test avalanche/complete diffusion on zeros\n");
    for (int i = 0; i < 48; i++) {
        buf[i] = 0;
    }
    printf("Changing 1 byte should create a completely different hash: buf[3] set to 1\n");
    buf[3] = 1;
    p152hash(buf, 25, out, 36);
    pbuf(out, 36, "zeros 25:");
    
    return 0;
}
#endif