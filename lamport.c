/**
    Name        : Why should I name it? I's my son, but actually I hate it ¯\_(ツ)_/¯
    Author      : Arget
    Version     : 0.5a
    Date        : 16/11/2017
    Description : A simple implementation of the Lamport-Diffie signature
    Notes       : Compile with `gcc -o lamport lamport.c base64.c -lcrypto'
*/

#include "lamport.h"
#include "base64.h"

int main(int argc, char** argv)
{
    // Multipurpose variables
    FILE* f;
    int i, j, k;
    int mask;

    // Flags-variable determined by the parameters
    char action;

    // Used in the signing process
    char* msgfile;

    // Will content the hash of the message
    uint8_t hash[HASH_SIZE_BYTES];

    // 16 KiB of random data, to be used as the private key
    uint8_t privkey[HASH_SIZE_BITS][2][HASH_SIZE_BYTES];

    // Hashes of each 'HASH_SIZE_BYTES' bytes in the previous matrix,
    // to be used as public key
    uint8_t pubkey[HASH_SIZE_BITS][2][HASH_SIZE_BYTES];
    
    // The final signature of the message's hash
    uint8_t signature[HASH_SIZE_BITS * HASH_SIZE_BYTES];

    // Initializing variables
    action = 0;

    progname = argv[0];

    // Obv.
    if(argc < 2)
        usage("[!] At least one argument required");


    /** Parsing arguments **/
    if(argv[1][0] == '-') // The 1st argument should start with '-'
    {
        if(!argv[1][1])   // The 1st argument is _just_ "-"
        {
            action = 1;
            msgfile = NULL; // The message comes from stdin
        }
        else
        {
            switch(argv[1][1])
            {
                case 's':
                    if(argc < 4)
                        usage("[!] msgfile missing");
                    action = 1;
                    msgfile = argv[3];
                    break;
                case 'g':
                    action = 2;
                    break;
                case 'v':
                    action = 4;
                    break;
                case 'p':
                    action = 8;
                    break;
                case 'h':
                    usage(NULL);
                    break; // Needless, usage() doesn't return :'(
                           // Just to keep the code "symmetry"

                default:
                    usage("[!] Invalid parameter");
            }
        }
    }
    else // I need the user to tell me what the fuck should I do
         // So I'll have to teach her/him to use this shitty program
        usage("[!] You don't know how to use this program, so...");
    
    if(action & 0x1) // Signing
    {
        if(argc < 3)
            usage("[!] I need the privfile");
        

        // Read the private key from the provided privfile
        printf("[+] Reading the private key from %s\n", argv[2]);
        readkey(argv[2], privkey);

        // Obtaining the hash of the message, wherever it comes from
        puts("[+] Signing the message . . .");
        sha256file(msgfile, hash);

        // Performing the "calculation" of the signature (a very very *hard* process)
        for(i = j = 0; i < HASH_SIZE_BYTES; i++)
        {
            for(k = 0, mask = 0x80; k < 8; k++, j++, mask /= 2)
                memcpy(signature + (j * HASH_SIZE_BYTES), privkey[j][(hash[i] & mask)?1:0], HASH_SIZE_BYTES);
        }

        // If the user specified outfile, we write the signature in that file,
        // instead of printing it in base64
        if((!msgfile && argc > 3) || (msgfile && argc > 4))
        {
            if(!msgfile)
                // Let's reuse this var, which is no longer needed (just like me :( )
                action = 3;
            else
                action = 4;
            printf("[+] Writing signature to %s\n", argv[action]);
            if(!(f = fopen(argv[action], "w")))
                panic("Error opening the file specified", -1, argv[action]);
            if(!fwrite(signature, sizeof(char), sizeof signature, f))
                panic("Error writing to the file specified", -1, argv[action]);
            fclose(f);
        }
        else
        {
            // Otherwise, print the base64 encoded signature
            bs64len = Base64encode_len(HASH_SIZE_BYTES * HASH_SIZE_BITS);
            bs64 = malloc(bs64len);
            Base64encode(bs64, signature, HASH_SIZE_BYTES * HASH_SIZE_BITS);
            puts("-----BEGIN LAMPORT SIGNATURE-----");
            for(i = 0; i < bs64len; i += 64)
                printf("\n%.64s", &bs64[i]);
            puts("\n-----END LAMPORT SIGNATURE-----");
            free(bs64);
        }
    }
    else
    if(action & 0x2) // Generate keypair
    {
        if(argc > 2 && argc < 4)
            usage("[!] You can not specify only privkey,\n"
                  "    you have to specify both privkey and pubkey, or none");

        puts("[+] Calculating Lamport keypair . . .");
        // Obtaining random data from a secure source to be used as the private key
        puts("[+] Obtaining random data from a secure source (may take a while)");
        if(!(f = fopen(RANDOMSRC, "r")))
            panic("Error opening the random source", -1, RANDOMSRC);
        if(!(fread(privkey, 1, sizeof privkey, f)))
            panic("Error reading from the random source", -1, RANDOMSRC);
        fclose(f);

        // Got the private key. Let's compute the public one
        puts("[+] Computing the public key from the private one");
        for(i = 0; i < HASH_SIZE_BITS; i++)
        {
            hashfunc(pubkey[i][0], privkey[i][0]);
            hashfunc(pubkey[i][1], privkey[i][1]);
        }

        if(argc > 2) // If the user specified privfile and pubfile,
                     // we write the keys in those files,
                     // instead of printing them in base64
        {
            printf("[+] Writing private key to %s\n", argv[2]);
            if(!(f = fopen(argv[2], "w")))
                panic("Error opening the file specified", -1, argv[2]);
            if(!fwrite(privkey, sizeof(char), sizeof privkey, f))
                panic("Error writing to the file specified", -1, argv[2]);
            fclose(f);

            printf("[+] Writing public key to %s\n", argv[3]);
            if(!(f = fopen(argv[3], "w")))
                panic("Error opening the file specified", -1, argv[3]);
            if(!fwrite(pubkey, sizeof(char), sizeof pubkey, f))
                panic("Error writing to the file specified", -1, argv[3]);
            fclose(f);
        }
        else
        {
            puts("[+] Here you have your keys. Enjoy!\n\n");
            // Print the private key in base64
            bs64len = Base64encode_len(sizeof privkey);
            bs64 = malloc(bs64len);
            Base64encode(bs64, privkey[0][0], sizeof privkey);
            puts("-----BEGIN LAMPORT PRIVATE KEY BLOCK-----");
            for(i = 0; i < bs64len; i += 64)
                printf("\n%.64s", &bs64[i]);
            puts("\n-----END LAMPORT PRIVATE KEY BLOCK-----\n\n");

            // And now print the public one in base64 codification
            // Note:
            //   sizeof pubkey == sizeof privkey, so Base64encode_len() would
            //   return the same value as before, so we don't need to free bs64
            //   and allocate it again
            Base64encode(bs64, pubkey[0][0], sizeof pubkey);
            puts("-----BEGIN LAMPORT PUBLIC KEY BLOCK-----");
            for(i = 0; i < bs64len; i += 64)
                printf("\n%.64s", &bs64[i]);
            puts("\n-----END LAMPORT PUBLIC KEY BLOCK-----");
            free(bs64);
        }
    }
    else
    if(action & 0x4) // Verifying a signature
    {
        if(argc < 5)
            usage("[!] Missing arguments");

        // Read the private key from the provided privfile
        printf("[+] Reading the public key from %s\n", argv[2]);
        readkey(argv[2], pubkey);

        // Now, read the signature from the signfile
        printf("[+] Reading the signature from %s\n", argv[3]);
        if(!(f = fopen(argv[3], "r")))
        panic("Error opening the file", -1, argv[3]);
        if(fread(signature, 1, (HASH_SIZE_BITS * HASH_SIZE_BYTES), f)
           != (HASH_SIZE_BITS * HASH_SIZE_BYTES))
            panic("signfile too small", 0, argv[3]);
        fclose(f);

        // We need the hash of the message
        sha256file(argv[4], hash);

        // Let's compute the hashes of the values from the signature
        puts("[+] Computing the hashes of the values from the signature");
        for(i = 0; i < (HASH_SIZE_BITS * HASH_SIZE_BYTES); i += HASH_SIZE_BYTES)
            hashfunc(&signature[i], &signature[i]);

        // Finally we validate the signature
        printf("[+] Validating signature\n");
        action = 0; // I'm gonna reuse this var, nobody will miss her...
        // Check every bit, byte by byte
        for(i = j = 0; i < HASH_SIZE_BYTES; i++, j += 8)
        {
            // Checking bits individually                              // 10000000b
            if(memcmp(signature+((j+0)*HASH_SIZE_BYTES), pubkey[j+0][(hash[i] & 0x80)?1:0], HASH_SIZE_BYTES) ||
                                                                       // 01000000b
               memcmp(signature+((j+1)*HASH_SIZE_BYTES), pubkey[j+1][(hash[i] & 0x40)?1:0], HASH_SIZE_BYTES) ||
                                                                       // 00100000b
               memcmp(signature+((j+2)*HASH_SIZE_BYTES), pubkey[j+2][(hash[i] & 0x20)?1:0], HASH_SIZE_BYTES) ||
                                                                       // 00010000b
               memcmp(signature+((j+3)*HASH_SIZE_BYTES), pubkey[j+3][(hash[i] & 0x10)?1:0], HASH_SIZE_BYTES) ||
                                                                       // 00001000b
               memcmp(signature+((j+4)*HASH_SIZE_BYTES), pubkey[j+4][(hash[i] & 0x08)?1:0], HASH_SIZE_BYTES) ||
                                                                       // 00000100b
               memcmp(signature+((j+5)*HASH_SIZE_BYTES), pubkey[j+5][(hash[i] & 0x04)?1:0], HASH_SIZE_BYTES) ||
                                                                       // 00000010b
               memcmp(signature+((j+6)*HASH_SIZE_BYTES), pubkey[j+6][(hash[i] & 0x02)?1:0], HASH_SIZE_BYTES) ||
                                                                       // 00000001b
               memcmp(signature+((j+7)*HASH_SIZE_BYTES), pubkey[j+7][(hash[i] & 0x01)?1:0], HASH_SIZE_BYTES))
            {
                // Somewhere (at j-th byte), something didn't fit, so the signature isn't correct
                action = 1;
                break;
            }
        }
        if(action)
            printf("[!] Found an error in byte %d\n"
                   "[!] INVALID signature.\n"
                   "LOL Something strange happened...\n"
                   " ... or someone is doing something nasty", j);
        else
            printf("[*] VALID signature\n"
                   "The message's integrity is ensured, as long as the issuer's\n"
                   "  private key has not been compromised, who knows?");
    }
    else
    if(action & 0x8) // Obtain the public key given a private key
    {
        if(argc < 3)
            usage("[!] I need the privfile");
        
        // Read the private key from the provided privfile
        printf("[+] Reading the private key from %s\n", argv[2]);
        readkey(argv[2], privkey);

        // Now let's compute the public key
        puts("[+] Computing the public key from the private one");
        for(i = 0; i < HASH_SIZE_BITS; i++)
        {
            hashfunc(pubkey[i][0], privkey[i][0]);
            hashfunc(pubkey[i][1], privkey[i][1]);
        }

        if(argc < 4) // If the user hasn't gave me a file in which write to
        {
            puts("[+] Here you have your public key. Enjoy! c:\n\n");
            bs64len = Base64encode_len(sizeof pubkey);
            bs64 = malloc(bs64len);
            Base64encode(bs64, pubkey[0][0], sizeof pubkey);
            puts("-----BEGIN LAMPORT PUBLIC KEY BLOCK-----");
            for(i = 0; i < bs64len; i += 64)
                printf("\n%.64s", &bs64[i]);
            puts("\n-----END LAMPORT PUBLIC KEY BLOCK-----");
            free(bs64);
        }
        else
        {
            printf("[+] Writing public key to %s\n", argv[3]);
            if(!(f = fopen(argv[3], "w")))
                panic("Error opening the file specified", -1, argv[3]);
            if(!fwrite(pubkey, sizeof(char), sizeof pubkey, f))
                panic("Error writing to the file specified", -1, argv[3]);
            fclose(f);
        }
    }
    
    putchar('\n');
    
    return 0;
}

void sha256file(const uint8_t* filename, uint8_t* hash)
{
    uint8_t readbuffer[BUFSIZE];
    size_t r;
    FILE* f;
    SHA256_CTX sha256;

    SHA256_Init(&sha256);
    if(filename)
    {
        printf("[+] Reading from %s\n[+] Computing the hash...", filename);
        fflush(stdout);
        f = fopen(filename, "r");
        if(!f)
            panic("Error opening the file specified", -1, filename);
        while(!feof(f))
        {
            r = fread(readbuffer, 1, BUFSIZE, f);
            SHA256_Update(&sha256, readbuffer, r);
        }
        fclose(f);
    }
    else
    {
        puts("[+] Reading from stdin, go ahead, type your message, don't be afraid");
        while(r = fread(readbuffer, 1, BUFSIZE, stdin))
            SHA256_Update(&sha256, readbuffer, r);
        printf("[+] Computing the hash... ");
        fflush(stdout);
    }

    SHA256_Final(hash, &sha256);

    // Print the hash just calculated
    printf(" Hash of the message (%s):\n", hashalgorithm);
    for(r = 0; r < HASH_SIZE_BYTES; r++)
        printf("%02x", hash[r]);
    puts("\n");
}

void sha256(uint8_t dst[HASH_SIZE_BYTES], const uint8_t src[HASH_SIZE_BYTES])
{
    SHA256_CTX sha256;

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, src, HASH_SIZE_BYTES);
    SHA256_Final(dst, &sha256);
}

void panic(const char* s, const int code,
           const char* justonemorething)
{
    fprintf(stderr, "[!] ");
    if(!justonemorething) fprintf(stderr, "%s: ", progname);
    else                  fprintf(stderr, "%s: \"%s\": ", progname, justonemorething);
    if(code)
    {
        perror(s);
        exit(code);
    }
    //else    // exit() will never return, deal with it
    fprintf(stderr, s);
    exit(1);
}

void usage(const char* s)
{
    if(s) puts(s);

    printf("Usage:\n"
           "\tGenerate a keypair\n"
           "\t  %1$s -g [outfile1 outfile2]\n\n"

           "\tSign\n"
           "\t  %1$s -s privfile msgfile [outfile]\n"
           "\t  %1$s -  privfile [outfile]\n\n"
    
           "\tVerify a signature\n"
           "\t  %1$s -v pubfile signfile msgfile\n\n"
       
           "\tGiven a private key, obtain the public key\n"
           "\t  %1$s -p privfile [outfile]\n\n"

           "\tPrint this message\n"
           "\t  %1$s -h\n\n"

           "Note:\n"
           "\tprivfile and pubfile must contain in raw the private and public keys,\n"
           "\t  respectively.\n"
           "\toutfile will content the resulting data in raw format.\n", progname);
    exit(1);
}

void readkey(const uint8_t* filename,
             uint8_t keyarray[HASH_SIZE_BITS][2][HASH_SIZE_BYTES])
{
    FILE* f;

    if(!(f = fopen(filename, "r")))
        panic("Error opening the file", -1, filename);
    
    if(fread(keyarray, 1, (HASH_SIZE_BITS * HASH_SIZE_BYTES * 2), f)
       != (HASH_SIZE_BITS * HASH_SIZE_BYTES * 2))
        panic("Keyfile too small", 0, filename);

    fclose(f);
}
