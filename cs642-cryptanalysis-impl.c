////////////////////////////////////////////////////////////////////////////////
//
//  File           : cs642-cryptanalysis-impl.c
//  Description    : This is the development program for the cs642 first project
//  that
//                   performs cryptanalysis on ciphertext of different ciphers.
//                   See associated documentation for more information.
//
//   Author        : Max Mitchell
//   Last Modified : October 14th, 2024
//

// Include Files
#include <compsci642_log.h>
// My imports
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>   

// Project Include Files
#include "cs642-cryptanalysis-support.h"

// Global Assignment

char *global_plaintext_buffer = NULL;
int buffer_size = 0;

double english_freq[26] = {
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153,
    0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056,
    2.758, 0.978, 2.360, 0.150, 1.974, 0.074
};

//
// Functions

// Helper functions

////////////////////////////////////////////////////////////////////////////////
//
// Function     : computeChiSquared
// Description  : Helper function to compute the Chi-squared statistic
//
// Inputs       : observed - the observed letter frequencies
//                expected - the expected letter frequencies    
//                clen - the length of the text
// Outputs      : the computed Chi-squared statistic

double computeChiSq(double observed[], double expected[], int clen) {
    double chi_sq_val = 0.0;
    for (int i = 0; i < 26; i++) {
        double expected_count = expected[i] * clen / 100.0;
        chi_sq_val += ((observed[i] - expected_count) * (observed[i] - expected_count)) / expected_count;
    }
    return chi_sq_val;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : inverseMod
// Description  : Helper function to compute the modular inverse of a number
//
// Inputs       : a - the number to find the modular inverse of
//                mod - the modulus
// Outputs      : the modular inverse of a

int inverseMod(int a, int mod) {

    for (int x = 1; x < mod * 2; x++) {
        if ((a * (x % mod)) % mod == 1) {
            return x % mod;
        }
    }
    return -1; 
}


////////////////////////////////////////////////////////////////////////////////
//
// Function     : decryptAffine
// Description  : Helper function to decrypt an Affine cipher
//
// Inputs       : ciphertext - the ciphertext to decrypt
//                clen - the length of the ciphertext
//                plaintext - the place to put the plaintext in
//                a - the 'a' value of the Affine cipher
//                b - the 'b' value of the Affine cipher
// Outputs      : void

// Helped to make the execution of the Affine cipher more efficient !
void decryptAffine(char *ciphertext, int clen, char *plaintext, int a, int b) {
    int a_i = inverseMod(a, 26);
    if (a_i == -1) {
        // Error checking
        return;
    }

    for (int i = 0; i < clen; i++) {
        if (isalpha(ciphertext[i])) {
            char base = islower(ciphertext[i]) ? 'a' : 'A';
            int y = ciphertext[i] - base;
            int x = (a_i * (y - b + 26)) % 26;

            if (i < clen) {
                plaintext[i] = x + base;
            }
        } else if (i < clen) {
            plaintext[i] = ciphertext[i];
        }
    }
    // Null Terminate
    plaintext[clen] = '\0';
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : findBestCaesarShift
// Description  : Helper function to find the best Caesar shift for a group
//
// Inputs       : group - the group to analyze
//                group_length - the length of the group
// Outputs      : the best Caesar shift

char findBestCaesarShift(char *group, int group_length) {
    // Initialize variables in this scope
    double best_chi_squared = 1e10;
    int best_shift = 0;
    
    char decrypted_group[group_length + 1]; 

    for (int shift = 0; shift < 26; shift++) {
        cs642Decrypt(CIPHER_ROTX, (char *)&shift, sizeof(shift), decrypted_group, group_length, group, group_length);

        // Null terminate
        decrypted_group[group_length] = '\0';

        // Calculate frequency
        double observed_freq[26] = {0};
        for (int i = 0; i < group_length; i++) {
            if (isalpha(decrypted_group[i])) {
                char base = islower(decrypted_group[i]) ? 'a' : 'A';
                observed_freq[decrypted_group[i] - base]++;
            }
        }

        // Compute Chi-sq statistic
        double chi_squared_val = computeChiSq(observed_freq, english_freq, group_length);

        // Update the best shift
        if (chi_squared_val < best_chi_squared) {
            best_chi_squared = chi_squared_val;
            best_shift = shift;
        }
    }

    return (char)('A' + best_shift);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : computeIC
// Description  : Helper function to compute the Index of Coincidence
//
// Inputs       : text - the text to analyze
//                tlen - the length of the text
// Outputs      : the computed Index of Coincidence

double computeIC(char *text, int tlen) {
    int letter_count[26] = {0}; // Letter frequency array
    int total_letters = 0;

    // Count letter frequencies
    for (int i = 0; i < tlen; i++) {
        if (isalpha(text[i])) {
            letter_count[toupper(text[i]) - 'A']++;
            total_letters++;
        }
    }

    // IC using the formula
    double ic = 0.0;
    for (int i = 0; i < 26; i++) {
        ic += letter_count[i] * (letter_count[i] - 1);
    }

    if (total_letters > 1) {
        ic /= (double)(total_letters * (total_letters - 1)); 
    }

    return ic;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : estKeyLen
// Description  : Helper function to estimate the key length of a Vigenere cipher
//
// Inputs       : ciphertext - the ciphertext to analyze
//                clen - the length of the ciphertext
// Outputs      : the estimated key length

int estKeyLen(char *cText, int cLen) {
    int maxLen = 20;
    double targetIC = 0.068;
    double minICDiff = 1e10;
    int bestLen = 1;

    for (int kLen = 1; kLen <= maxLen; kLen++) {
        double avgIC = 0.0;

        for (int grp = 0; grp < kLen; grp++) {
            // Allocate group buffer
            int maxGrpLen = (cLen / kLen) + 2;
            char *grpText = (char *)malloc(maxGrpLen * sizeof(char));

            int grpLen = 0;
            for (int idx = grp; idx < cLen; idx += kLen) {
                // Check for space
                if (grpLen < maxGrpLen - 1) {  
                    grpText[grpLen++] = cText[idx];
                }
            }
            // Null Terminate
            grpText[grpLen] = '\0';

            avgIC += computeIC(grpText, grpLen);

            // Free heap memory
            free(grpText);
        }

        avgIC /= kLen;

        double icDiff = fabs(avgIC - targetIC);

        // Find best key length
        if (icDiff < minICDiff) {
            minICDiff = icDiff;
            bestLen = kLen;
        }
    }

    return bestLen;
}




// Given functions


////////////////////////////////////////////////////////////////////////////////
//
// Function     : cs642StudentInit
// Description  : This is a function that is called before any cryptanalysis
//                occurs. Use it if you need to initialize some datastructures
//                you may be reusing across ciphers.
//
// Inputs       : void
// Outputs      : 0 if successful, -1 if failure

int cs642StudentInit(void) {

    // General buffer for plaintext

    // Make sure to check buffer in each function !!! 
    // Leading to errors
    buffer_size = 1024;
    global_plaintext_buffer = (char *)malloc(buffer_size * sizeof(char));
    
    if (global_plaintext_buffer == NULL) {
        return -1;
    }

    return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : cs642PerformROTXCryptanalysis
// Description  : This is the function to cryptanalyze the ROT X cipher
//
// Inputs       : ciphertext - the ciphertext to analyze
//                clen - the length of the ciphertext
//                plaintext - the place to put the plaintext in
//                plen - the length of the plaintext
//                key - the place to put the key in
// Outputs      : 0 if successful, -1 if failure

int cs642PerformROTXCryptanalysis(char *ciphertext, int clen, char *plaintext,
                                  int plen, uint8_t *key) {

    // Check buffer
    if (clen > buffer_size) {
        char *temp_buffer = realloc(global_plaintext_buffer, (clen + 1) * sizeof(char));
        global_plaintext_buffer = temp_buffer;
        buffer_size = clen + 1;
    }

    // Initialize variables
    double best_chi_squared = 1e10;
    int best_key = 0;

    // Try all possible keys
    for (int i = 0; i < 26; i++) {
        // Use the provided cs642Decrypt
        cs642Decrypt(CIPHER_ROTX, (char *)&i, sizeof(i), global_plaintext_buffer, clen, ciphertext, clen);

        // Calculate frequency
        double observed_freq[26] = {0};
        for (int j = 0; j < clen; j++) {
            if (isalpha(global_plaintext_buffer[j])) {
                char base = islower(global_plaintext_buffer[j]) ? 'a' : 'A';
                observed_freq[global_plaintext_buffer[j] - base]++;
            }
        }

        // Compute Chi-sq statistic
        double chi_squared = computeChiSq(observed_freq, english_freq, clen);

        // Find the best key
        if (chi_squared < best_chi_squared) {
            best_chi_squared = chi_squared;
            best_key = i;
            strncpy(plaintext, global_plaintext_buffer, plen); 
        }
    }

    *key = (uint8_t)best_key;

    return 0;
}



////////////////////////////////////////////////////////////////////////////////
//
// Function     : cs642PerformAFFICryptanalysis
// Description  : This is the function to cryptanalyze the Affine cipher
//
// Inputs       : ciphertext - the ciphertext to analyze
//                clen - the length of the ciphertext
//                plaintext - the place to put the plaintext in
//                plen - the length of the plaintext
//                key - the place to put the key in (8-bit packed value)
// Outputs      : 0 if successful, -1 if failure
//
int cs642PerformAFFICryptanalysis(char *ciphertext, int clen, char *plaintext, int plen, uint8_t *key) {
    // Check buffer
    if (clen > buffer_size) {
        char *temp_buffer = realloc(global_plaintext_buffer, (clen + 1) * sizeof(char));
        global_plaintext_buffer = temp_buffer;
        buffer_size = clen + 1;
    }

    // List of possible a
    int possible_a_values[] = {1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25};
    int num_a_values = sizeof(possible_a_values) / sizeof(possible_a_values[0]);

    double best_chi_squared = 1e10;
    int best_a_index = 0, best_b = 0;

    // Try all combinations of 'a' and 'b'
    for (int i = 0; i < num_a_values; i++) {
        int a = possible_a_values[i];
        for (int b = 0; b < 26; b++) {
            // Need own helper for this particular decryption
            decryptAffine(ciphertext, clen, global_plaintext_buffer, a, b);

            // Calculate letter frequencies in the decrypted text
            double observed_freq[26] = {0};
            for (int j = 0; j < clen; j++) {
                if (isalpha(global_plaintext_buffer[j])) {
                    char base = islower(global_plaintext_buffer[j]) ? 'a' : 'A';
                    observed_freq[global_plaintext_buffer[j] - base]++;
                }
            }

            // Compute the Chi-sq statistic
            double chi_squared = computeChiSq(observed_freq, english_freq, clen);

            // Update the best key
            if (chi_squared < best_chi_squared) {
                best_chi_squared = chi_squared;
                best_a_index = i;
                best_b = b;
                strncpy(plaintext, global_plaintext_buffer, plen); 
            }
        }
    }

    // Assign a and b
    key[0] = (uint8_t)possible_a_values[best_a_index];  
    key[1] = (uint8_t)best_b; 

    // Create a char array for the key
    char aff_key[2] = {(char)key[0], (char)key[1]};

    // Decrypt using cs642Decrypt
    cs642Decrypt(CIPHER_AFFI, aff_key, sizeof(aff_key), plaintext, plen, ciphertext, clen);

    return 0;
}


////////////////////////////////////////////////////////////////////////////////
//
// Function     : cs642PerformVIGECryptanalysis
// Description  : This is the function to cryptanalyze the Vigenere cipher
//
// Inputs       : ciphertext - the ciphertext to analyze
//                clen - the length of the ciphertext
//                plaintext - the place to put the plaintext in
//                plen - the length of the plaintext
//                key - the place to put the key in
// Outputs      : 0 if successful, -1 if failure

int cs642PerformVIGECryptanalysis(char *ciphertext, int clen, char *plaintext,
                                  int plen, char *key) {
    
    // Estimate key
    int estimated_key_length = estKeyLen(ciphertext, clen);
    
    // Memory allocation
    char **caesar_groups = (char **)malloc(estimated_key_length * sizeof(char *));
    for (int i = 0; i < estimated_key_length; i++) {
        // Allocate enough space considering remainder
        int group_size = (clen + estimated_key_length - 1) / estimated_key_length + 1;
        caesar_groups[i] = (char *)malloc(group_size * sizeof(char));
    }

    // Group the ciphertext 
    for (int i = 0; i < clen; i++) {
        int group_index = i % estimated_key_length;
        int position_in_group = i / estimated_key_length;
        caesar_groups[group_index][position_in_group] = ciphertext[i];
    }

    // Null Terminate
    for (int i = 0; i < estimated_key_length; i++) {
        int group_size = (clen + estimated_key_length - 1) / estimated_key_length;
        caesar_groups[i][group_size] = '\0';
    }
    
    // Search for best shift
    for (int i = 0; i < estimated_key_length; i++) {
        key[i] = findBestCaesarShift(caesar_groups[i], (clen + estimated_key_length - 1) / estimated_key_length);
    }
    
    // Null Terminate
    key[estimated_key_length] = '\0';
    
    // Use the cs642Decrypt function
    cs642Decrypt(CIPHER_VIGE, key, estimated_key_length, plaintext, plen, ciphertext, clen);
    
    // Free !!
    for (int i = 0; i < estimated_key_length; i++) {
        free(caesar_groups[i]);
    }
    free(caesar_groups);
    
    return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : cs642PerformSUBSCryptanalysis
// Description  : This is the function to cryptanalyze the substitution cipher
//
// Inputs       : ciphertext - the ciphertext to analyze
//                clen - the length of the ciphertext
//                plaintext - the place to put the plaintext in
//                plen - the length of the plaintext
//                key - the place to put the key in
// Outputs      : 0 if successful, -1 if failure

int cs642PerformSUBSCryptanalysis(char *ciphertext, int clen, char *plaintext,
                                  int plen, char *key) {

  // ADD CODE HERE
    // No time to finish this one with the midterm tomorrow!
  // Return successfully
  return (0);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : cs642StudentCleanUp
// Description  : This is a clean up function called at the end of the
//                cryptanalysis of the different ciphers. Use it if you need to
//                release memory you allocated in cs642StudentInit() for
//                instance.
//
// Inputs       : void
// Outputs      : 0 if successful, -1 if failure

int cs642StudentCleanUp(void) {

    // Free the global buffer
    if (global_plaintext_buffer != NULL) {
        free(global_plaintext_buffer);
        global_plaintext_buffer = NULL;
    }

    // Return success
    return 0;
}
