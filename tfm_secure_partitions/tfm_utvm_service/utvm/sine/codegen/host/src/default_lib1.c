// tvm target: c -keys=cpu -link-params=0 -mcpu=cortex-m33
#define TVM_EXPORTS
#include "tvm/runtime/c_runtime_api.h"
#include "tvm/runtime/c_backend_api.h"
#include <math.h>

#ifdef __cplusplus
extern "C" {
#endif
static const float __attribute__((section(".rodata.tvm"), aligned(16))) constant_5[1] = {
    -0x1.928ffp-2
};
#ifdef __cplusplus
}  // extern "C"
#endif

#ifdef __cplusplus
extern "C" {
#endif
static const float __attribute__((section(".rodata.tvm"), aligned(16))) constant_4[16] = {
    -0x1.34a976p-1, -0x1.f681e2p-1, 0x1.0a4db6p-1, 0x1.315aeep-1, 0x1.bb42f6p-1, 0x1.874a72p+0, -0x1.1cb848p-3, 0x1.ece3ecp-3, 
    -0x1.163b78p+0, 0x1.02674ep+0, 0x1.47fcf4p+0, 0x1.6b359ep-2, 0x1.d688acp-2, 0x1.7d1c46p-4, 0x1.919aa8p-2, 0x1.06c20ap-2
};
#ifdef __cplusplus
}  // extern "C"
#endif

#ifdef __cplusplus
extern "C" {
#endif
static const float __attribute__((section(".rodata.tvm"), aligned(16))) constant_1[16] = {
    -0x1.705acp-8, -0x1.be4b42p-1, 0x0p+0   , -0x1.ae434ep-1, 0x0p+0   , 0x0p+0   , 0x1.69f32ap-2, 0x0p+0   , 
    -0x1.83002ap-2, 0x1.52c81p-1, 0x0p+0   , 0x1.bb143ep-4, 0x0p+0   , -0x1.607a2ap-2, 0x0p+0   , 0x1.efecdp-4
};
#ifdef __cplusplus
}  // extern "C"
#endif

#ifdef __cplusplus
extern "C" {
#endif
static const float __attribute__((section(".rodata.tvm"), aligned(16))) constant_0[16] = {
    -0x1.748b24p-10, 0x1.9221acp-2, -0x1.eadf2p-5, 0x1.bb7fa6p-2, -0x1.a4b9f4p-3, -0x1.891b3p-2, 0x1.1dc37cp-2, -0x1.0d4696p-2, 
    0x1.5bd82cp-2, -0x1.54c802p-6, -0x1.02ed28p-1, 0x1.76ab46p-2, -0x1.e9cb2p-5, 0x1.a9bd74p-2, -0x1.7277c8p-3, 0x1.45bdcp-2
};
#ifdef __cplusplus
}  // extern "C"
#endif

#ifdef __cplusplus
extern "C" {
#endif
static const float __attribute__((section(".rodata.tvm"), aligned(16))) constant_3[16] = {
    0x1.fd2108p-3, 0x1.f30ae2p-2, -0x1.d09a7cp-6, -0x1.95900cp-2, 0x1.7c19d4p-2, -0x1.116d0ep-1, 0x1.023c88p-2, -0x1.e458b8p-4, 
    0x1.f73d3ap-2, 0x1.80a63p-2, 0x1.8d54a2p-2, -0x1.a2a39ep-4, -0x1.6f478ap-2, -0x1.d1d082p-4, 0x0p+0   , -0x1.39f4b4p-5
};
#ifdef __cplusplus
}  // extern "C"
#endif

#ifdef __cplusplus
extern "C" {
#endif
static const float __attribute__((section(".rodata.tvm"), aligned(16))) constant_2[256] = {
    -0x1.4a62b2p-2, -0x1.27d47ap-2, -0x1.9df19p-4, 0x1.1a687p-2, 0x1.578812p-2, -0x1.b4ecf8p-3, 0x1.0bf31ap-1, 0x1.1d114p-7, 
    0x1.7eaf3ep-2, -0x1.0c1d42p-3, 0x1.8ff9ccp-3, 0x1.2058c4p-2, -0x1.171848p-2, -0x1.814e96p-2, 0x1.288a16p-2, 0x1.84020cp-4, 
    -0x1.8c75ap-3, -0x1.ceb414p-3, 0x1.141896p-2, -0x1.037c52p-3, -0x1.15d46cp-2, -0x1.da9a62p-3, -0x1.c92952p-2, 0x1.3b5a2cp-3, 
    -0x1.11d4c6p-1, 0x1.786e5ep-2, -0x1.b0608p-8, 0x1.c5a728p-4, -0x1.7d799p-4, 0x1.aa0074p-2, -0x1.e4d14p-4, -0x1.d0ceeap-3, 
    -0x1.4457fp-5, -0x1.28ec9p-4, -0x1.7764dcp-2, 0x1.2731bp-3, -0x1.6f779ap-2, -0x1.70866p-3, -0x1.9495ep-2, -0x1.2de994p-2, 
    -0x1.c3edd8p-3, 0x1.b4c794p-3, -0x1.e4e1cp-3, -0x1.429bfp-3, -0x1.2038a8p-2, -0x1.a2f246p-5, 0x1.cfd444p-3, -0x1.af4b5cp-2, 
    0x1.ee096ap-3, 0x1.13662p-1, -0x1.c344b4p-3, 0x1.ad9eacp-2, -0x1.28a278p-3, 0x1.de3e38p-4, -0x1.7380eap-2, -0x1.3713a4p-3, 
    0x1.80aeb8p-2, -0x1.3e75d8p-2, 0x1.387c4ep-2, -0x1.10eb1ap-4, -0x1.fbda38p-4, 0x1.9c9aaap-5, 0x1.456924p-3, 0x1.dcbbaap-4, 
    -0x1.aa9a3ep-3, -0x1.3eaa5p-7, -0x1.a90daep-2, -0x1.60311p-4, -0x1.732f48p-3, 0x1.985e86p-2, 0x1.17451ap-2, -0x1.af4e8p-3, 
    -0x1.d8f728p-2, 0x1.0c64c4p-1, 0x1.2bb1acp-3, 0x1.9d5ddp-3, 0x1.a0f35cp-3, -0x1.637444p-2, 0x1.bafdb4p-3, -0x1.02c7ap-2, 
    0x1.4e7fd4p-2, 0x1.516548p-1, -0x1.d3814p-5, 0x1.c673e4p-3, -0x1.fadc78p-4, 0x1.71c7ep-6, -0x1.022986p-1, 0x1.714192p-2, 
    0x1.0ce4fap-2, -0x1.9b2246p-1, 0x1.aeb0bcp-3, 0x1.3f4eap-2, -0x1.121a4p-3, 0x1.fde56cp-5, 0x1.d8aa78p-4, -0x1.67c8ep-3, 
    0x1.22d84ep-2, 0x1.09062p-5, -0x1.9994b8p-4, -0x1.bf0b8cp-2, 0x1.2d77eap-2, -0x1.01015cp-2, 0x1.e010a4p-3, 0x1.a640d8p-4, 
    0x1.799d52p-2, -0x1.51f626p-5, -0x1.1faef8p-3, -0x1.0f4bep-2, 0x1.13728ep-2, 0x1.42c418p-2, -0x1.9b39aap-2, 0x1.6d4146p-3, 
    -0x1.fcbcep-5, 0x1.b672b6p-4, 0x1.b10ac4p-3, -0x1.05663ep-3, 0x1.bb6c08p-4, -0x1.20ab4p-2, -0x1.86973ap-2, -0x1.970062p-3, 
    0x1.e752e2p-4, 0x1.17f1ep-3, -0x1.2cf28p-5, 0x1.f088cep-3, -0x1.31f8e8p-3, -0x1.1f2326p-3, 0x1.e55648p-4, -0x1.37ef1p-2, 
    -0x1.12804p-2, -0x1.9804dep-5, 0x1.87b7a6p-2, -0x1.0a9118p-1, 0x1.4f5fdep-2, 0x1.a6e714p-3, -0x1.4e5408p-1, 0x1.84378ep-2, 
    -0x1.557d98p-7, 0x1.4a2ce6p-1, 0x1.4b0d24p-3, 0x1.63006cp-5, 0x1.cc57c8p-4, 0x1.0c9d5ap-8, 0x1.babf74p-3, -0x1.5ab17cp-1, 
    0x1.12ab02p-2, -0x1.2d22f8p-1, 0x1.871cp-5, -0x1.33bfb8p-2, 0x1.a79f98p-4, -0x1.1f1cbp-2, 0x1.6a5f58p-2, -0x1.61495cp-2, 
    -0x1.c994bep-2, 0x1.1c3da6p-1, 0x1.2ff546p-2, 0x1.98ab24p-2, 0x1.bd01cp-6, -0x1.015716p-2, 0x1.7e0d74p-3, -0x1.6e059p-4, 
    -0x1.04a48cp-3, -0x1.4c006cp-1, 0x1.5c0be4p-3, -0x1.49346p-4, 0x1.3dfed4p-3, 0x1.932d8cp-3, -0x1.72cd0ep-3, -0x1.e43cd2p-3, 
    -0x1.17c7bcp-2, -0x1.ad4e3p-3, -0x1.f6928p-6, 0x1.cef292p-3, 0x1.33ec54p-3, 0x1.95c6f8p-4, 0x1.616694p-3, 0x1.f6499cp-3, 
    0x1.8ef55cp-3, -0x1.455b66p-2, -0x1.7e528p-5, -0x1.78f806p-2, 0x1.ef1bdp-5, -0x1.33b69p-5, -0x1.2613cp-2, 0x1.047d44p-3, 
    -0x1.82a544p-2, 0x1.e40f3p-9, -0x1.5953a8p-2, 0x1.3f3696p-2, -0x1.131cecp-2, -0x1.695d7ep-4, -0x1.a42088p-2, -0x1.9a494ap-2, 
    0x1.f65e8cp-3, 0x1.78b4bcp-3, -0x1.bb9d0cp-3, 0x1.66cb14p-2, 0x1.105ap-8, -0x1.25589cp-2, 0x1.6c37f8p-2, -0x1.4acca4p-2, 
    0x1.58d8dap-3, -0x1.f11b08p-2, 0x1.15aad4p-3, 0x1.958c2cp-6, 0x1.81c196p-2, -0x1.eab428p-6, -0x1.9f6f7p-3, -0x1.612b58p-3, 
    0x1.b6ca6ap-2, 0x1.830a54p-3, -0x1.b88844p-2, -0x1.c78f4p-7, 0x1.abad44p-3, 0x1.388338p-4, -0x1.3ceb26p-4, -0x1.14fdb8p-4, 
    -0x1.b1a0cp-4, 0x1.2e593ap-2, -0x1.ed79c6p-3, -0x1.d41052p-2, 0x1.6ab122p-2, -0x1.4e91eep-3, 0x1.35216p-6, -0x1.68ec12p-4, 
    0x1.3cc78p-7, -0x1.8742eep-2, 0x1.c57524p-3, -0x1.159abp-5, -0x1.436ad8p-3, 0x1.8ec8d6p-2, -0x1.13bcdp-2, 0x1.336bfap-2, 
    0x1.c2a54cp-3, -0x1.236f88p-4, 0x1.c154dcp-3, -0x1.04a016p-2, -0x1.3eb78ep-2, -0x1.65da1cp-2, -0x1.19a1d4p-2, 0x1.7f4b8cp-3, 
    0x1.81cd06p-2, 0x1.a2462ap-5, -0x1.08c5d8p-4, 0x1.21d9f8p-3, -0x1.14207cp-2, 0x1.16e68p-7, -0x1.be6facp-4, -0x1.2377dcp-2, 
    0x1.4c5f0cp-2, -0x1.cc61cep-3, -0x1.c25c3ap-3, 0x1.1c2af2p-4, 0x1.57ff34p-3, -0x1.18f064p-2, 0x1.a6d34ap-2, -0x1.16c984p-3
};
#ifdef __cplusplus
}  // extern "C"
#endif
#ifdef __cplusplus
extern "C"
#endif
TVM_DLL int32_t tvmgen_default_fused_nn_dense_add(float* placeholder, float* T_add) {
  float packed_weight[16];
  float compute_global[1];
  for (int32_t y = 0; y < 16; ++y) {
    packed_weight[y] = ((float*)constant_4)[y];
  }
  compute_global[0] = 0.000000e+00f;
  for (int32_t k_outer = 0; k_outer < 16; ++k_outer) {
    compute_global[0] = (compute_global[0] + (placeholder[k_outer] * packed_weight[k_outer]));
  }
  T_add[0] = (compute_global[0] + ((float*)constant_5)[0]);
  return 0;
}

#ifdef __cplusplus
extern "C"
#endif
TVM_DLL int32_t tvmgen_default_fused_nn_dense_add_nn_relu(float* placeholder, float* T_relu) {
  float packed_weight[16];
  for (int32_t z = 0; z < 2; ++z) {
    for (int32_t x = 0; x < 8; ++x) {
      int32_t cse_var_1 = ((z * 8) + x);
      packed_weight[cse_var_1] = ((float*)constant_0)[cse_var_1];
    }
  }
  for (int32_t ax1_outer_ax0_outer_fused = 0; ax1_outer_ax0_outer_fused < 2; ++ax1_outer_ax0_outer_fused) {
    float compute_global[8];
    for (int32_t x_c_init = 0; x_c_init < 8; ++x_c_init) {
      compute_global[x_c_init] = 0.000000e+00f;
    }
    for (int32_t x_c = 0; x_c < 8; ++x_c) {
      compute_global[x_c] = (compute_global[x_c] + (placeholder[0] * packed_weight[((ax1_outer_ax0_outer_fused * 8) + x_c)]));
    }
    for (int32_t ax1_inner_inner = 0; ax1_inner_inner < 8; ++ax1_inner_inner) {
      int32_t cse_var_2 = ((ax1_outer_ax0_outer_fused * 8) + ax1_inner_inner);
      float _1 = compute_global[ax1_inner_inner] + ((float*)constant_1)[cse_var_2];
      T_relu[cse_var_2] = ((_1) > (0.000000e+00f) ? (_1) : (0.000000e+00f));
    }
  }
  return 0;
}

#ifdef __cplusplus
extern "C"
#endif
TVM_DLL int32_t tvmgen_default_fused_nn_dense_add_nn_relu_1(float* placeholder, float* T_relu) {
  void* packed_weight = TVMBackendAllocWorkspace(1, 0, (uint64_t)1024, 2, 32);
  if (packed_weight == NULL) {
    return -1;
  }
  for (int32_t z = 0; z < 2; ++z) {
    for (int32_t y = 0; y < 16; ++y) {
      for (int32_t x = 0; x < 8; ++x) {
        int32_t cse_var_1 = (z * 128);
        ((float*)packed_weight)[((cse_var_1 + (y * 8)) + x)] = ((float*)constant_2)[((cse_var_1 + (x * 16)) + y)];
      }
    }
  }
  for (int32_t ax1_outer_ax0_outer_fused = 0; ax1_outer_ax0_outer_fused < 2; ++ax1_outer_ax0_outer_fused) {
    float compute_global[8];
    for (int32_t x_c_init = 0; x_c_init < 8; ++x_c_init) {
      compute_global[x_c_init] = 0.000000e+00f;
    }
    for (int32_t k_outer = 0; k_outer < 16; ++k_outer) {
      for (int32_t x_c = 0; x_c < 8; ++x_c) {
        compute_global[x_c] = (compute_global[x_c] + (placeholder[k_outer] * ((float*)packed_weight)[(((ax1_outer_ax0_outer_fused * 128) + (k_outer * 8)) + x_c)]));
      }
    }
    for (int32_t ax1_inner_inner = 0; ax1_inner_inner < 8; ++ax1_inner_inner) {
      int32_t cse_var_2 = ((ax1_outer_ax0_outer_fused * 8) + ax1_inner_inner);
      float _1 = compute_global[ax1_inner_inner] + ((float*)constant_3)[cse_var_2];
      T_relu[cse_var_2] = ((_1) > (0.000000e+00f) ? (_1) : (0.000000e+00f));
    }
  }
  if (TVMBackendFreeWorkspace(1, 0, packed_weight) != 0) {
    return -1;
  }
  return 0;
}

#ifdef __cplusplus
extern "C"
#endif
TVM_DLL int32_t tvmgen_default_fused_reshape(float* placeholder, float* T_reshape) {
  T_reshape[0] = placeholder[0];
  return 0;
}

#ifdef __cplusplus
extern "C"
#endif
TVM_DLL int32_t tvmgen_default_fused_reshape_1(float* placeholder, float* T_reshape) {
  for (int32_t ax1_inner = 0; ax1_inner < 16; ++ax1_inner) {
    T_reshape[ax1_inner] = placeholder[ax1_inner];
  }
  return 0;
}

#ifdef __cplusplus
extern "C"
#endif
TVM_DLL int32_t tvmgen_default___tvm_main__(float* dense_4_input_buffer_var, float* output_buffer_var) {
  void* sid_6 = TVMBackendAllocWorkspace(1, 0, (uint64_t)64, 0, 8);
  if (sid_6 == NULL) {
    return -1;
  }
  void* sid_5 = TVMBackendAllocWorkspace(1, 0, (uint64_t)64, 0, 8);
  if (sid_5 == NULL) {
    return -1;
  }
  if (tvmgen_default_fused_reshape(dense_4_input_buffer_var, sid_6) != 0 ) return -1;
  if (tvmgen_default_fused_nn_dense_add_nn_relu(sid_6, sid_5) != 0 ) return -1;
  if (tvmgen_default_fused_reshape_1(sid_5, sid_6) != 0 ) return -1;
  if (tvmgen_default_fused_nn_dense_add_nn_relu_1(sid_6, sid_5) != 0 ) return -1;
  if (tvmgen_default_fused_reshape_1(sid_5, sid_6) != 0 ) return -1;
  if (tvmgen_default_fused_nn_dense_add(sid_6, output_buffer_var) != 0 ) return -1;
  if (TVMBackendFreeWorkspace(1, 0, sid_5) != 0) {
    return -1;
  }
  if (TVMBackendFreeWorkspace(1, 0, sid_6) != 0) {
    return -1;
  }
  return 0;
}

