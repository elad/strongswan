/*
 * Copyright (C) 2014 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "bliss_fft_params.h"

/**
 * FFT parameters for q = 12289 and 2n = 2048
 */
static uint16_t w_12289_2048[] = {
	    1,     7,    49,   343,  2401,  4518,  7048,   180,  1260,  8820,
	  295,  2065,  2166,  2873,  7822,  5598,  2319,  3944,  3030,  8921,
	 1002,  7014, 12231, 11883,  9447,  4684,  8210,  8314,  9042,  1849,
	  654,  4578,  7468,  3120,  9551,  5412,  1017,  7119,   677,  4739,
	 8595, 11009,  3329, 11014,  3364, 11259,  5079, 10975,  3091,  9348,
	 3991,  3359, 11224,  4834,  9260,  3375, 11336,  5618,  2459,  4924,
	 9890,  7785,  5339,   506,  3542,   216,  1512, 10584,   354,  2478,
	 5057, 10821,  2013,  1802,   325,  2275,  3636,   874,  6118,  5959,
	 4846,  9344,  3963,  3163,  9852,  7519,  3477, 12050, 10616,   578,
	 4046,  3744,  1630, 11410,  6136,  6085,  5728,  3229, 10314, 10753,

	 1537, 10759,  1579, 11053,  3637,   881,  6167,  6302,  7247,  1573,
	11011,  3343, 11112,  4050,  3772,  1826,   493,  3451, 11868,  9342,
	 3949,  3065,  9166,  2717,  6730, 10243, 10256, 10347, 10984,  3154,
	 9789,  7078,   390,  2730,  6821, 10880,  2426,  4693,  8273,  8755,
	12129, 11169,  4449,  6565,  9088,  2171,  2908,  8067,  7313,  2035,
	 1956,  1403,  9821,  7302,  1958,  1417,  9919,  7988,  6760, 10453,
	11726,  8348,  9280,  3515,    27,   189,  1323,  9261,  3382, 11385,
	 5961,  4860,  9442,  4649,  7965,  6599,  9326,  3837,  2281,  3678,
	 1168,  8176,  8076,  7376,  2476,  5043, 10723,  1327,  9289,  3578,
	  468,  3276, 10643,   767,  5369,   716,  5012, 10506, 12097, 10945,

	 2881,  7878,  5990,  5063, 10863,  2307,  3860,  2442,  4805,  9057,
	 1954,  1389,  9723,  6616,  9445,  4670,  8112,  7628,  4240,  5102,
	11136,  4218,  4948, 10058,  8961,  1282,  8974,  1373,  9611,  5832,
	 3957,  3121,  9558,  5461,  1360,  9520,  5195, 11787,  8775, 12269,
	12149, 11309,  5429,  1136,  7952,  6508,  8689, 11667,  7935,  6389,
	 7856,  5836,  3985,  3317, 10930,  2776,  7143,   845,  5915,  4538,
	 7188,  1160,  8120,  7684,  4632,  7846,  5766,  3495, 12176, 11498,
	 6752, 10397, 11334,  5604,  2361,  4238,  5088, 11038,  3532,   146,
	 1022,  7154,   922,  6454,  8311,  9021,  1702, 11914,  9664,  6203,
	 6554,  9011,  1632, 11424,  6234,  6771, 10530, 12265, 12121, 11113,

	 4057,  3821,  2169,  2894,  7969,  6627,  9522,  5209, 11885,  9461,
	 4782,  8896,   827,  5789,  3656,  1014,  7098,   530,  3710,  1392,
	 9744,  6763, 10474, 11873,  9377,  4194,  4780,  8882,   729,  5103,
	11143,  4267,  5291,   170,  1190,  8330,  9154,  2633,  6142,  6127,
	 6022,  5287,   142,   994,  6958, 11839,  9139,  2528,  5407,   982,
	 6874, 11251,  5023, 10583,   347,  2429,  4714,  8420,  9784,  7043,
	  145,  1015,  7105,   579,  4053,  3793,  1973,  1522, 10654,   844,
	 5908,  4489,  6845, 11048,  3602,   636,  4452,  6586,  9235,  3200,
	10111,  9332,  3879,  2575,  5736,  3285, 10706,  1208,  8456, 10036,
	 8807,   204,  1428,  9996,  8527, 10533, 12286, 12268, 12142, 11260,

	 5086, 11024,  3434, 11749,  8509, 10407, 11404,  6094,  5791,  3670,
	 1112,  7784,  5332,   457,  3199, 10104,  9283,  3536,   174,  1218,
	 8526, 10526, 12237, 11925,  9741,  6742, 10327, 10844,  2174,  2929,
	 8214,  8342,  9238,  3221, 10258, 10361, 11082,  3840,  2302,  3825,
	 2197,  3090,  9341,  3942,  3016,  8823,   316,  2212,  3195, 10076,
	 9087,  2164,  2859,  7724,  4912,  9806,  7197,  1223,  8561, 10771,
	 1663, 11641,  7753,  5115, 11227,  4855,  9407,  4404,  6250,  6883,
	11314,  5464,  1381,  9667,  6224,  6701, 10040,  8835,   400,  2800,
	 7311,  2021,  1858,   717,  5019, 10555,   151,  1057,  7399,  2637,
	 6170,  6323,  7394,  2602,  5925,  4608,  7678,  4590,  7552,  3708,

	 1378,  9646,  6077,  5672,  2837,  7570,  3834,  2260,  3531,   139,
	  973,  6811, 10810,  1936,  1263,  8841,   442,  3094,  9369,  4138,
	 4388,  6138,  6099,  5826,  3915,  2827,  7500,  3344, 11119,  4099,
	 4115,  4227,  5011, 10499, 12048, 10602,   480,  3360, 11231,  4883,
	 9603,  5776,  3565,   377,  2639,  6184,  6421,  8080,  7404,  2672,
	 6415,  8038,  7110,   614,  4298,  5508,  1689, 11823,  9027,  1744,
	12208, 11722,  8320,  9084,  2143,  2712,  6695,  9998,  8541, 10631,
	  683,  4781,  8889,   778,  5446,  1255,  8785,    50,   350,  2450,
	 4861,  9449,  4698,  8308,  9000,  1555, 10885,  2461,  4938,  9988,
	 8471, 10141,  9542,  5349,   576,  4032,  3646,   944,  6608,  9389,

	 4278,  5368,   709,  4963, 10163,  9696,  6427,  8122,  7698,  4730,
	 8532, 10568,   242,  1694, 11858,  9272,  3459, 11924,  9734,  6693,
	 9984,  8443,  9945,  8170,  8034,  7082,   418,  2926,  8193,  8195,
	 8209,  8307,  8993,  1506, 10542,    60,   420,  2940,  8291,  8881,
	  722,  5054, 10800,  1866,   773,  5411,  1010,  7070,   334,  2338,
	 4077,  3961,  3149,  9754,  6833, 10964,  3014,  8809,   218,  1526,
	10682,  1040,  7280,  1804,   339,  2373,  4322,  5676,  2865,  7766,
	 5206, 11864,  9314,  3753,  1693, 11851,  9223,  3116,  9523,  5216,
	11934,  9804,  7183,  1125,  7875,  5969,  4916,  9834,  7393,  2595,
	 5876,  4265,  5277,    72,   504,  3528,   118,   826,  5782,  3607,

	  671,  4697,  8301,  8951,  1212,  8484, 10232, 10179,  9808,  7211,
	 1321,  9247,  3284, 10699,  1159,  8113,  7635,  4289,  5445,  1248,
	 8736, 11996, 10238, 10221, 10102,  9269,  3438, 11777,  8705, 11779,
	 8719, 11877,  9405,  4390,  6152,  6197,  6512,  8717, 11863,  9307,
	 3704,  1350,  9450,  4705,  8357,  9343,  3956,  3114,  9509,  5118,
	11248,  5002, 10436, 11607,  7515,  3449, 11854,  9244,  3263, 10552,
	  130,   910,  6370,  7723,  4905,  9757,  6854, 11111,  4043,  3723,
	 1483, 10381, 11222,  4820,  9162,  2689,  6534,  8871,   652,  4564,
	 7370,  2434,  4749,  8665, 11499,  6759, 10446, 11677,  8005,  6879,
	11286,  5268,     9,    63,   441,  3087,  9320,  3795,  1987,  1620,

	11340,  5646,  2655,  6296,  7205,  1279,  8953,  1226,  8582, 10918,
	 2692,  6555,  9018,  1681, 11767,  8635, 11289,  5289,   156,  1092,
	 7644,  4352,  5886,  4335,  5767,  3502, 12225, 11841,  9153,  2626,
	 6093,  5784,  3621,   769,  5383,   814,  5698,  3019,  8844,   463,
	 3241, 10398, 11341,  5653,  2704,  6639,  9606,  5797,  3712,  1406,
	 9842,  7449,  2987,  8620, 11184,  4554,  7300,  1944,  1319,  9233,
	 3186, 10013,  8646, 11366,  5828,  3929,  2925,  8186,  8146,  7866,
	 5906,  4475,  6747, 10362, 11089,  3889,  2645,  6226,  6715, 10138,
	 9521,  5202, 11836,  9118,  2381,  4378,  6068,  5609,  2396,  4483,
	 6803, 10754,  1544, 10808,  1922,  1165,  8155,  7929,  6347,  7562,

	 3778,  1868,   787,  5509,  1696, 11872,  9370,  4145,  4437,  6481,
	 8500, 10344, 10963,  3007,  8760, 12164, 11414,  6164,  6281,  7100,
	  544,  3808,  2078,  2257,  3510, 12281, 12233, 11897,  9545,  5370,
	  723,  5061, 10849,  2209,  3174,  9929,  8058,  7250,  1594, 11158,
	 4372,  6026,  5315,   338,  2366,  4273,  5333,   464,  3248, 10447,
	11684,  8054,  7222,  1398,  9786,  7057,   243,  1701, 11907,  9615,
	 5860,  4153,  4493,  6873, 11244,  4974, 10240, 10235, 10200,  9955,
	 8240,  8524, 10512, 12139, 11239,  4939,  9995,  8520, 10484, 11943,
	 9867,  7624,  4212,  4906,  9764,  6903, 11454,  6444,  8241,  8531,
	10561,   193,  1351,  9457,  4754,  8700, 11744,  8474, 10162,  9689,

	 6378,  7779,  5297,   212,  1484, 10388, 11271,  5163, 11563,  7207,
	 1293,  9051,  1912,  1095,  7665,  4499,  6915, 11538,  7032,    68,
	  476,  3332, 11035,  3511, 12288, 12282, 12240, 11946,  9888,  7771,
	 5241, 12109, 11029,  3469, 11994, 10224, 10123,  9416,  4467,  6691,
	 9970,  8345,  9259,  3368, 11287,  5275,    58,   406,  2842,  7605,
	 4079,  3975,  3247, 10440, 11635,  7711,  4821,  9169,  2738,  6877,
	11272,  5170, 11612,  7550,  3694,  1280,  8960,  1275,  8925,  1030,
	 7210,  1314,  9198,  2941,  8298,  8930,  1065,  7455,  3029,  8914,
	  953,  6671,  9830,  7365,  2399,  4504,  6950, 11783,  8747, 12073,
	10777,  1705, 11935,  9811,  7232,  1468, 10276, 10487, 11964, 10014,

	 8653, 11415,  6171,  6330,  7443,  2945,  8326,  9126,  2437,  4770,
	 8812,   239,  1673, 11711,  8243,  8545, 10659,   879,  6153,  6204,
	 6561,  9060,  1975,  1536, 10752,  1530, 10710,  1236,  8652, 11408,
	 6122,  5987,  5042, 10716,  1278,  8946,  1177,  8239,  8517, 10463,
	11796,  8838,   421,  2947,  8340,  9224,  3123,  9572,  5559,  2046,
	 2033,  1942,  1305,  9135,  2500,  5211, 11899,  9559,  5468,  1409,
	 9863,  7596,  4016,  3534,   160,  1120,  7840,  5724,  3201, 10118,
	 9381,  4222,  4976, 10254, 10333, 10886,  2468,  4987, 10331, 10872,
	 2370,  4301,  5529,  1836,   563,  3941,  3009,  8774, 12262, 12100,
	10966,  3028,  8907,   904,  6328,  7429,  2847,  7640,  4324,  5690,

	 2963,  8452, 10008,  8611, 11121,  4113,  4213,  4913,  9813,  7246,
	 1566, 10962,  3000,  8711, 11821,  9013,  1646, 11522,  6920, 11573,
	 7277,  1783,   192,  1344,  9408,  4411,  6299,  7226,  1426,  9982,
	 8429,  9847,  7484,  3232, 10335, 10900,  2566,  5673,  2844,  7619,
	 4177,  4661,  8049,  7187,  1153,  8071,  7341,  2231,  3328, 11007,
	 3315, 10916,  2678,  6457,  8332,  9168,  2731,  6828, 10929,  2769,
	 7094,   502,  3514,    20,   140,   980,  6860, 11153,  4337,  5781,
	 3600,   622,  4354,  5900,  4433,  6453,  8304,  8972,  1359,  9513,
	 5146, 11444,  6374,  7751,  5101, 11129,  4169,  4605,  7657,  4443,
	 6523,  8794,   113,   791,  5537,  1892,   955,  6685,  9928,  8051,

	 7201,  1251,  8757, 12143, 11267,  5135, 11367,  5835,  3978,  3268,
	10587,   375,  2625,  6086,  5735,  3278, 10657,   865,  6055,  5518,
	 1759,    24,   168,  1176,  8232,  8468, 10120,  9395,  4320,  5662,
	 2767,  7080,   404,  2828,  7507,  3393, 11462,  6500,  8633, 11275,
	 5191, 11759,  8579, 10897,  2545,  5526,  1815,   416,  2912,  8095,
	 7509,  3407, 11560,  7186,  1146,  8022,  6998, 12119, 11099,  3959,
	 3135,  9656,  6147,  6162,  6267,  7002, 12147, 11295,  5331,   450,
	 3150,  9761,  6882, 11307,  5415,  1038,  7266,  1706, 11942,  9860,
	 7575,  3869,  2505,  5246, 12144, 11274,  5184, 11710,  8236,  8496,
	10316, 10767,  1635, 11445,  6381,  7800,  5444,  1241,  8687, 11653,

	 7837,  5703,  3054,  9089,  2178,  2957,  8410,  9714,  6553,  9004,
	 1583, 11081,  3833,  2253,  3482, 12085, 10861,  2293,  3762,  1756,
	    3,    21,   147,  1029,  7203,  1265,  8855,   540,  3780,  1882,
	  885,  6195,  6498,  8619, 11177,  4505,  6957, 11832,  9090,  2185,
	 3006,  8753, 12115, 11071,  3763,  1763,    52,   364,  2548,  5547,
	 1962,  1445, 10115,  9360,  4075,  3947,  3051,  9068,  2031,  1928,
	 1207,  8449,  9987,  8464, 10092,  9199,  2948,  8347,  9273,  3466,
	11973, 10077,  9094,  2213,  3202, 10125,  9430,  4565,  7377,  2483,
	 5092, 11066,  3728,  1518, 10626,   648,  4536,  7174,  1062,  7434,
	 2882,  7885,  6039,  5406,   975,  6825, 10908,  2622,  6065,  5588,

	 2249,  3454, 11889,  9489,  4978, 10268, 10431, 11572,  7270,  1734,
	12138, 11232,  4890,  9652,  6119,  5966,  4895,  9687,  6364,  7681,
	 4611,  7699,  4737,  8581, 10911,  2643,  6212,  6617,  9452,  4719,
	 8455, 10029,  8758, 12150, 11316,  5478,  1479, 10353, 11026,  3448,
	11847,  9195,  2920,  8151,  7901,  6151,  6190,  6463,  8374,  9462,
	 4789,  8945,  1170,  8190,  8174,  8062,  7278,  1790,   241,  1687,
	11809,  8929,  1058,  7406,  2686,  6513,  8724, 11912,  9650,  6105,
	 5868,  4209,  4885,  9617,  5874,  4251,  5179, 11675,  7991,  6781,
	10600,   466,  3262, 10545,    81,   567,  3969,  3205, 10146,  9577,
	 5594,  2291,  3748,  1658, 11606,  7508,  3400, 11511,  6843, 11034,

	 3504, 12239, 11939,  9839,  7428,  2840,  7591,  3981,  3289, 10734,
	 1404,  9828,  7351,  2301,  3818,  2148,  2747,  6940, 11713,  8257,
	 8643, 11345,  5681,  2900,  8011,  6921, 11580,  7326,  2126,  2593,
	 5862,  4167,  4591,  7559,  3757,  1721, 12047, 10595,   431,  3017,
	 8830,   365,  2555,  5596,  2305,  3846,  2344,  4119,  4255,  5207,
	11871,  9363,  4096,  4094,  4080,  3982,  3296, 10783,  1747, 12229,
	11869,  9349,  3998,  3408, 11567,  7235,  1489, 10423, 11516,  6878,
	11279,  5219, 11955,  9951,  8212,  8328,  9140,  2535,  5456,  1325,
	 9275,  3480, 12071, 10763,  1607, 11249,  5009, 10485, 11950,  9916,
	 7967,  6613,  9424,  4523,  7083,   425,  2975,  8536, 10596,   438,

	 3066,  9173,  2766,  7073,   355,  2485,  5106, 11164,  4414,  6320,
	 7373,  2455,  4896,  9694,  6413,  8024,  7012, 12217, 11785,  8761,
	12171, 11463,  6507,  8682, 11618,  7592,  3988,  3338, 11077,  3805,
	 2057,  2110,  2481,  5078, 10968,  3042,  9005,  1590, 11130,  4176,
	 4654,  8000,  6844, 11041,  3553,   293,  2051,  2068,  2187,  3020,
	 8851,   512,  3584,   510,  3570,   412,  2884,  7899,  6137,  6092,
	 5777,  3572,   426,  2982,  8585, 10939,  2839,  7584,  3932,  2946,
	 8333,  9175,  2780,  7171,  1041,  7287,  1853,   682,  4774,  8840,
	  435,  3045,  9026,  1737, 12159, 11379,  5919,  4566,  7384,  2532,
	 5435,  1178,  8246,  8566, 10806,  1908,  1067,  7469,  3127,  9600,

	 5755,  3418, 11637,  7725,  4919,  9855,  7540,  3624,   790,  5530,
	 1843,   612,  4284,  5410,  1003,  7021, 12280, 12226, 11848,  9202,
	 2969,  8494, 10302, 10669,   949,  6643,  9634,  5993,  5084, 11010,
	 3336, 11063,  3707,  1371,  9597,  5734,  3271, 10608,   522,  3654,
	 1000,  7000, 12133, 11197,  4645,  7937,  6403,  7954,  6522,  8787,
	   64,   448,  3136,  9663,  6196,  6505,  8668, 11520,  6906, 11475,
	 6591,  9270,  3445, 11826,  9048,  1891,   948,  6636,  9585,  5650,
	 2683,  6492,  8577, 10883,  2447,  4840,  9302,  3669,  1105,  7735,
	 4989, 10345, 10970,  3056,  9103,  2276,  3643,   923,  6461,  8360,
	 9364,  4103,  4143,  4423,  6383,  7814,  5542,  1927,  1200,  8400,

	 9644,  6063,  5574,  2151,  2768,  7087,   453,  3171,  9908,  7911,
	 6221,  6680,  9893,  7806,  5486,  1535, 10745,  1481, 10367, 11124,
	 4134,  4360,  5942,  4727,  8511, 10421, 11502,  6780, 10593,   417,
	 2919,  8144,  7852,  5808,  3789,  1945,  1326,  9282,  3529,   125,
	  875,  6125,  6008,  5189, 11745,  8481, 10211, 10032,  8779,     8,
	   56,   392,  2744,  6919, 11566,  7228,  1440, 10080,  9115,  2360,
	 4231,  5039, 10695,  1131,  7917,  6263,  6974, 11951,  9923,  8016,
	 6956, 11825,  9041,  1842,   605,  4235,  5067, 10891,  2503,  5232,
	12046, 10588,   382,  2674,  6429,  8136,  7796,  5416,  1045,  7315,
	 2049,  2054,  2089,  2334,  4049,  3765,  1777,   150,  1050,  7350,

	 2294,  3769,  1805,   346,  2422,  4665,  8077,  7383,  2525,  5386,
	  835,  5845,  4048,  3758,  1728, 12096, 10938,  2832,  7535,  3589,
	  545,  3815,  2127,  2600,  5911,  4510,  6992, 12077, 10805,  1901,
	 1018,  7126,   726,  5082, 10996,  3238, 10377, 11194,  4624,  7790,
	 5374,   751,  5257, 12221, 11813,  8957,  1254,  8778,     1
};

/**
 * Bit-reversed indices for n = 1024
 */
static uint16_t rev_1024[] = {
	   0,  512,  256,  768,  128,  640,  384,  896,   64,  576,
	 320,  832,  192,  704,  448,  960,   32,  544,  288,  800,
	 160,  672,  416,  928,   96,  608,  352,  864,  224,  736,
	 480,  992,   16,  528,  272,  784,  144,  656,  400,  912,
	  80,  592,  336,  848,  208,  720,  464,  976,   48,  560,
	 304,  816,  176,  688,  432,  944,  112,  624,  368,  880,
	 240,  752,  496, 1008,    8,  520,  264,  776,  136,  648,
	 392,  904,   72,  584,  328,  840,  200,  712,  456,  968,
	  40,  552,  296,  808,  168,  680,  424,  936,  104,  616,
	 360,  872,  232,  744,  488, 1000,   24,  536,  280,  792,

	 152,  664,  408,  920,   88,  600,  344,  856,  216,  728,
	 472,  984,   56,  568,  312,  824,  184,  696,  440,  952,
	 120,  632,  376,  888,  248,  760,  504, 1016,    4,  516,
	 260,  772,  132,  644,  388,  900,   68,  580,  324,  836,
	 196,  708,  452,  964,   36,  548,  292,  804,  164,  676,
	 420,  932,  100,  612,  356,  868,  228,  740,  484,  996,
	  20,  532,  276,  788,  148,  660,  404,  916,   84,  596,
	 340,  852,  212,  724,  468,  980,   52,  564,  308,  820,
	 180,  692,  436,  948,  116,  628,  372,  884,  244,  756,
	 500, 1012,   12,  524,  268,  780,  140,  652,  396,  908,

	  76,  588,  332,  844,  204,  716,  460,  972,   44,  556,
	 300,  812,  172,  684,  428,  940,  108,  620,  364,  876,
	 236,  748,  492, 1004,   28,  540,  284,  796,  156,  668,
	 412,  924,   92,  604,  348,  860,  220,  732,  476,  988,
	  60,  572,  316,  828,  188,  700,  444,  956,  124,  636,
	 380,  892,  252,  764,  508, 1020,    2,  514,  258,  770,
	 130,  642,  386,  898,   66,  578,  322,  834,  194,  706,
	 450,  962,   34,  546,  290,  802,  162,  674,  418,  930,
	  98,  610,  354,  866,  226,  738,  482,  994,   18,  530,
	 274,  786,  146,  658,  402,  914,   82,  594,  338,  850,

	 210,  722,  466,  978,   50,  562,  306,  818,  178,  690,
	 434,  946,  114,  626,  370,  882,  242,  754,  498, 1010,
	  10,  522,  266,  778,  138,  650,  394,  906,   74,  586,
	 330,  842,  202,  714,  458,  970,   42,  554,  298,  810,
	 170,  682,  426,  938,  106,  618,  362,  874,  234,  746,
	 490, 1002,   26,  538,  282,  794,  154,  666,  410,  922,
	  90,  602,  346,  858,  218,  730,  474,  986,   58,  570,
	 314,  826,  186,  698,  442,  954,  122,  634,  378,  890,
	 250,  762,  506, 1018,    6,  518,  262,  774,  134,  646,
	 390,  902,   70,  582,  326,  838,  198,  710,  454,  966,

	  38,  550,  294,  806,  166,  678,  422,  934,  102,  614,
	 358,  870,  230,  742,  486,  998,   22,  534,  278,  790,
	 150,  662,  406,  918,   86,  598,  342,  854,  214,  726,
	 470,  982,   54,  566,  310,  822,  182,  694,  438,  950,
	 118,  630,  374,  886,  246,  758,  502, 1014,   14,  526,
	 270,  782,  142,  654,  398,  910,   78,  590,  334,  846,
	 206,  718,  462,  974,   46,  558,  302,  814,  174,  686,
	 430,  942,  110,  622,  366,  878,  238,  750,  494, 1006,
	  30,  542,  286,  798,  158,  670,  414,  926,   94,  606,
	 350,  862,  222,  734,  478,  990,   62,  574,  318,  830,

	 190,  702,  446,  958,  126,  638,  382,  894,  254,  766,
	 510, 1022,    1,  513,  257,  769,  129,  641,  385,  897,
	  65,  577,  321,  833,  193,  705,  449,  961,   33,  545,
	 289,  801,  161,  673,  417,  929,   97,  609,  353,  865,
	 225,  737,  481,  993,   17,  529,  273,  785,  145,  657,
	 401,  913,   81,  593,  337,  849,  209,  721,  465,  977,
	  49,  561,  305,  817,  177,  689,  433,  945,  113,  625,
	 369,  881,  241,  753,  497, 1009,    9,  521,  265,  777,
	 137,  649,  393,  905,   73,  585,  329,  841,  201,  713,
	 457,  969,   41,  553,  297,  809,  169,  681,  425,  937,

	 105,  617,  361,  873,  233,  745,  489, 1001,   25,  537,
	 281,  793,  153,  665,  409,  921,   89,  601,  345,  857,
	 217,  729,  473,  985,   57,  569,  313,  825,  185,  697,
	 441,  953,  121,  633,  377,  889,  249,  761,  505, 1017,
	   5,  517,  261,  773,  133,  645,  389,  901,   69,  581,
	 325,  837,  197,  709,  453,  965,   37,  549,  293,  805,
	 165,  677,  421,  933,  101,  613,  357,  869,  229,  741,
	 485,  997,   21,  533,  277,  789,  149,  661,  405,  917,
	  85,  597,  341,  853,  213,  725,  469,  981,   53,  565,
	 309,  821,  181,  693,  437,  949,  117,  629,  373,  885,

	 245,  757,  501, 1013,   13,  525,  269,  781,  141,  653,
	 397,  909,   77,  589,  333,  845,  205,  717,  461,  973,
	  45,  557,  301,  813,  173,  685,  429,  941,  109,  621,
	 365,  877,  237,  749,  493, 1005,   29,  541,  285,  797,
	 157,  669,  413,  925,   93,  605,  349,  861,  221,  733,
	 477,  989,   61,  573,  317,  829,  189,  701,  445,  957,
	 125,  637,  381,  893,  253,  765,  509, 1021,    3,  515,
	 259,  771,  131,  643,  387,  899,   67,  579,  323,  835,
	 195,  707,  451,  963,   35,  547,  291,  803,  163,  675,
	 419,  931,   99,  611,  355,  867,  227,  739,  483,  995,

	  19,  531,  275,  787,  147,  659,  403,  915,   83,  595,
	 339,  851,  211,  723,  467,  979,   51,  563,  307,  819,
	 179,  691,  435,  947,  115,  627,  371,  883,  243,  755,
	 499, 1011,   11,  523,  267,  779,  139,  651,  395,  907,
	  75,  587,  331,  843,  203,  715,  459,  971,   43,  555,
	 299,  811,  171,  683,  427,  939,  107,  619,  363,  875,
	 235,  747,  491, 1003,   27,  539,  283,  795,  155,  667,
	 411,  923,   91,  603,  347,  859,  219,  731,  475,  987,
	  59,  571,  315,  827,  187,  699,  443,  955,  123,  635,
	 379,  891,  251,  763,  507, 1019,    7,  519,  263,  775,

	 135,  647,  391,  903,   71,  583,  327,  839,  199,  711,
	 455,  967,   39,  551,  295,  807,  167,  679,  423,  935,
	 103,  615,  359,  871,  231,  743,  487,  999,   23,  535,
	 279,  791,  151,  663,  407,  919,   87,  599,  343,  855,
	 215,  727,  471,  983,   55,  567,  311,  823,  183,  695,
	 439,  951,  119,  631,  375,  887,  247,  759,  503, 1015,
	  15,  527,  271,  783,  143,  655,  399,  911,   79,  591,
	 335,  847,  207,  719,  463,  975,   47,  559,  303,  815,
	 175,  687,  431,  943,  111,  623,  367,  879,  239,  751,
	 495, 1007,   31,  543,  287,  799,  159,  671,  415,  927,

	  95,  607,  351,  863,  223,  735,  479,  991,   63,  575,
	 319,  831,  191,  703,  447,  959,  127,  639,  383,  895,
	 255,  767,  511, 1023
};

bliss_fft_params_t bliss_fft_12289_1024 = {
	12289, 1024, 12277, 10, w_12289_2048, 1, rev_1024
};

/**
 * Bit-reversed indices for n = 512
 */
static uint16_t rev_512[] = {
	  0, 256, 128, 384,  64, 320, 192, 448,  32, 288, 
	160, 416,  96, 352, 224, 480,  16, 272, 144, 400,
	 80, 336, 208, 464,  48, 304, 176, 432, 112, 368,
	240, 496,   8, 264, 136, 392,  72, 328, 200, 456,
	 40, 296, 168, 424, 104, 360, 232, 488,  24, 280,
	152, 408,  88, 344, 216, 472,  56, 312, 184, 440,
	120, 376, 248, 504,   4, 260, 132, 388,  68, 324,
	196, 452,  36, 292, 164, 420, 100, 356, 228, 484,
	 20, 276, 148, 404,  84, 340, 212, 468,  52, 308,
	180, 436, 116, 372, 244, 500,  12, 268, 140, 396,

	 76, 332, 204, 460,  44, 300, 172, 428, 108, 364,
	236, 492,  28, 284, 156, 412,  92, 348, 220, 476,
	 60, 316, 188, 444, 124, 380, 252, 508,   2, 258,
	130, 386,  66, 322, 194, 450,  34, 290, 162, 418,
	 98, 354, 226, 482,  18, 274, 146, 402,  82, 338,
	210, 466,  50, 306, 178, 434, 114, 370, 242, 498,
	 10, 266, 138, 394,  74, 330, 202, 458,  42, 298,
	170, 426, 106, 362, 234, 490,  26, 282, 154, 410,
	 90, 346, 218, 474,  58, 314, 186, 442, 122, 378,
	250, 506,   6, 262, 134, 390,  70, 326, 198, 454,

	 38, 294, 166, 422, 102, 358, 230, 486,  22, 278,
	150, 406,  86, 342, 214, 470,  54, 310, 182, 438,
	118, 374, 246, 502,  14, 270, 142, 398,  78, 334,
	206, 462,  46, 302, 174, 430, 110, 366, 238, 494,
	 30, 286, 158, 414,  94, 350, 222, 478,  62, 318,
	190, 446, 126, 382, 254, 510,   1, 257, 129, 385,
	 65, 321, 193, 449,  33, 289, 161, 417,  97, 353,
	225, 481,  17, 273, 145, 401,  81, 337, 209, 465,
	 49, 305, 177, 433, 113, 369, 241, 497,   9, 265,
	137, 393,  73, 329, 201, 457,  41, 297, 169, 425,

	105, 361, 233, 489,  25, 281, 153, 409,  89, 345,
	217, 473,  57, 313, 185, 441, 121, 377, 249, 505,
	  5, 261, 133, 389,  69, 325, 197, 453,  37, 293,
	165, 421, 101, 357, 229, 485,  21, 277, 149, 405,
	 85, 341, 213, 469,  53, 309, 181, 437, 117, 373,
	245, 501,  13, 269, 141, 397,  77, 333, 205, 461,
	 45, 301, 173, 429, 109, 365, 237, 493,  29, 285,
	157, 413,  93, 349, 221, 477,  61, 317, 189, 445,
	125, 381, 253, 509,   3, 259, 131, 387,  67, 323,
	195, 451,  35, 291, 163, 419,  99, 355, 227, 483,

	 19, 275, 147, 403,  83, 339, 211, 467,  51, 307,
	179, 435, 115, 371, 243, 499,  11, 267, 139, 395,
	 75, 331, 203, 459,  43, 299, 171, 427, 107, 363,
	235, 491,  27, 283, 155, 411,  91, 347, 219, 475,
	 59, 315, 187, 443, 123, 379, 251, 507,   7, 263,
	135, 391,  71, 327, 199, 455,  39, 295, 167, 423,
	103, 359, 231, 487,  23, 279, 151, 407,  87, 343,
	215, 471,  55, 311, 183, 439, 119, 375, 247, 503,
	 15, 271, 143, 399,  79, 335, 207, 463,  47, 303,
	175, 431, 111, 367, 239, 495,  31, 287, 159, 415,

	 95, 351, 223, 479,  63, 319, 191, 447, 127, 383,
	255, 511
};

bliss_fft_params_t bliss_fft_12289_512 = {
	12289, 512, 12265, 9, w_12289_2048, 2, rev_512
};

/**
 * FFT parameters for q = 17 and n = 16
 */
static uint16_t w_17_16[] = {
	1, 3, 9, 10, 13, 5, 15, 11, 16, 14, 8, 7, 4, 12, 2, 6, 1 };

/**
 * Bit-reversed indices for n = 8
 */
static uint16_t rev_8[] = { 0, 4, 2, 6, 1, 5, 3, 7 };

bliss_fft_params_t bliss_fft_17_8 = { 17, 8, 15, 3, w_17_16, 1, rev_8 };
